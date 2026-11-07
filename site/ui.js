/* SWCC · интерфейс верификатора. Читает globalThis.SWCC_CORE (core.js грузится
   раньше), строит карточки и обрабатывает ввод админа.

   Данные отчёта — недоверенный ввод: строки из payload попадают в DOM только
   через el()/textContent, никогда через innerHTML. Сети нет: файл читается
   FileReader'ом и живёт только в памяти вкладки.

   Словари (VERDICT_RU, RULE_RU, ROOT_KIND_RU) и памятьки — дословные копии
   src/swcc.rs, src/scanner.rs, src/paths.rs. Правишь строку в Rust — правишь тут. */

(function () {
  'use strict';

  var CORE = globalThis.SWCC_CORE;

  /* ------------------------------------------------------------------ словари
     Значения полей приходят из serde-сериализации; подписи — из ru() методов
     src/scanner.rs и src/signatures.rs, чтобы сайт и программа говорили одинаково. */

  var VERDICT_RU = {
    no_data: 'Данных нет',
    clean: 'Признаков не найдено',
    low_signal: 'Косвенные признаки',
    suspicious: 'Подозрение',
    high_risk: 'Высокий риск'
  };
  var VERDICT_ADVICE = {
    no_data: 'Сканирование не выполнено: не найдено ни одной папки игры, либо процесс прерван.',
    clean: 'Автоматических признаков не найдено. Это НЕ гарантия честной игры: база знает ограниченное число ' +
      'клиентов, а кастомный пересобранный чит она не увидит.',
    low_signal: 'Совпадения слабые или единичные. Бан по такому отчёту не обоснован.',
    suspicious: 'Нужна ручная проверка: запроси названные файлы и сравни их с официальными релизами.',
    high_risk: 'Несколько независимых признаков одного семейства либо критическое совпадение. ' +
      'Вероятность чит-клиента высокая - проверяй находки вручную перед решением.'
  };
  var VERDICT_TONE = {
    no_data: 'info', clean: 'clean', low_signal: 'medium', suspicious: 'high', high_risk: 'critical'
  };

  var SEVERITY_RU = {
    info: 'информация', low: 'низкая', medium: 'средняя', high: 'высокая', critical: 'критическая'
  };
  var SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  var SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

  var KIND_RU = {
    cheat_client: 'чит-клиент',
    autoclicker: 'автокликер',
    xray: 'x-ray',
    macro: 'макрос',
    injection: 'инъекция/агент',
    cracked_launcher: 'обход лицензии',
    grey_helper: 'серый помощник',
    config_leftover: 'остаточный конфиг',
    other: 'прочее'
  };

  // RuleKind сериализуется без rename_all — варианты с большой буквы.
  var RULE_RU = {
    FileName: 'имя файла',
    FilePath: 'путь файла',
    Directory: 'каталог',
    RawBytes: 'строка в байтах файла',
    ArchiveEntry: 'запись внутри архива',
    ArchiveContent: 'содержимое архива',
    TextContent: 'содержимое текста',
    LaunchLog: 'лог запуска',
    KnownHash: 'файл совпадает с известным признаком'
  };

  var ROOT_KIND_RU = {
    standard: 'стандартная',
    launcher_instance: 'инстанс лаунчера',
    manual: 'папка игры выбрана вручную',
    drive: 'обход по метаданным'
  };

  var CHECK_MEMO = [
    'Отчёт - повод для проверки, а не доказательство. Бан только по заключению сканера обосновать нельзя.',
    'Сверь названный файл с официальным релизом: пересобранный jar под именем легитимного мода - главный приём маскировки.',
    'Запроси у игрока сам файл (или ссылку на его публичный релиз) и путь к нему;совпадение пути в отчёте и присланного файла подтверждает находку.',
    'Смотри время изменения файлов: чит, скачанный за минуты до забан-события, и мод, установленный месяц назад, - это разные ситуации.',
    'Обнови базу сигнатур (signatures/custom.toml) при появлении нового клиента: встроенная база знает ограниченное число клиентов.',
    'Остаточный конфиг или удалённый клиент не оправдание: проверяй логи поведения на сервере.'
  ];
  var LIMIT_MEMO = [
    'Сканер ищет файлы по известным сигнатурам. Самописный или пересобранный чит он может не увидеть: чистый отчёт не равен честной игре.',
    'Ложные срабатывания возможны: совпадение имени или строки в легитимном моде - не чит. Поэтому у каждой находки указан признак и уверенность.',
    'Отчёт формируется на машине игрока, которую он контролирует. Печать ниже ловит случайную правку и повреждение файла, но не подделку: ключ печати находится в той же программе, что и у игрока.',
    'Отсюда вывод: решение принимай по совокупности - отчёт + запрошенные у игрока файлы + серверные логи поведения.'
  ];

  /* ------------------------------------------------------------- команда бана
     Строка `/ban <ник> <длительность> <причина>` выводится для любого заключения:
     решение принимает админ, а шаблон всегда под рукой. Для «чисто» и «косвенных
     признаков» длительность остаётся незаполненной — бан по такому отчёту не
     обоснован, и придумывать её за админа страница не должна. */
  var BAN_DURATION = {
    high_risk: '30d',
    suspicious: '7d'
  };
  var BAN_PRESETS = ['1h', '24h', '7d', '30d', 'permanent'];

  function banDraft(report, out) {
    var res = report.result || {};
    var env = res.environment || {};
    var fams = res.families || [];
    var reason = fams.length
      ? 'Читы: ' + fams.map(function (f) { return f.family; }).join(', ') +
        ' · отчёт ' + (report.id || '—') + (out.intact ? '' : ' (печать не подтверждена)')
      : (res.findings || []).length
        ? 'Читы по отчёту ' + (report.id || '—')
        : '';
    return {
      nick: report.player || env.nick_from_launch || '',
      duration: BAN_DURATION[res.verdict] || '',
      reason: reason
    };
  }

  function banText(d) {
    return '/ban ' + (d.nick || '<ник>') + ' ' + (d.duration || '<длительность>') +
      ' ' + (d.reason || '<причина>');
  }

  /* --------------------------------------------------------------------- утилиты */

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function push(parent) {
    for (var i = 1; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      parent.append(c);
    }
    return parent;
  }
  function $(id) { return document.getElementById(id); }

  function ru(dict, key, fallback) {
    if (key === null || key === undefined) return fallback !== undefined ? fallback : '—';
    return dict[key] !== undefined ? dict[key] : String(key);
  }

  function fmtInt(v) {
    if (v === null || v === undefined) return '—';
    var n = Number(v);
    if (!isFinite(n)) return String(v);
    return n.toLocaleString('ru-RU');
  }
  /* Русское согласование числительных: 1 файл / 2 файла / 5 файлов. */
  function plural(n, one, few, many) {
    var x = Math.abs(Math.round(Number(n)));
    if (!isFinite(x)) return fmtInt(n);
    var d1 = x % 10, d2 = x % 100;
    var word = (d1 === 1 && d2 !== 11) ? one
      : (d1 >= 2 && d1 <= 4 && !(d2 >= 12 && d2 <= 14)) ? few : many;
    return fmtInt(x) + ' ' + word;
  }
  function fmtBytes(v) {
    if (v === null || v === undefined) return '—';
    var n = Number(v);
    if (!isFinite(n)) return '—';
    if (n < 1024) return fmtInt(n) + ' Б';
    var units = ['КБ', 'МБ', 'ГБ', 'ТБ'], u = -1, x = n;
    do { x /= 1024; u++; } while (x >= 1024 && u < units.length - 1);
    return x.toLocaleString('ru-RU', { maximumFractionDigits: x < 10 ? 2 : 1 }) + ' ' + units[u] +
      ' (' + fmtInt(n) + ' Б)';
  }
  function fmtPct(conf) {
    var n = Number(conf);
    if (!isFinite(n)) return '—';
    return Math.round(n * 100) + '%';
  }

  var ISO_RE = /(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?([+\-]\d{2}:?\d{2}|Z)?/;
  // Разбираем RFC3339 сам: наносекунды из Rust Date.parse в браузере не переваривает,
  // а смещение в часовом поясе админа исказило бы метку. Поэтому:
  //   ms  — абсолютный момент (для разницы «сколько назад»),
  //   поля —Components метки как они записаны (для показа).
  function parseInstant(s) {
    if (typeof s !== 'string') return null;
    var m = ISO_RE.exec(s);
    if (!m) return null;
    var tz = m[8];
    var offMin = 0;
    if (tz && tz !== 'Z') {
      var sign = tz.charAt(0) === '-' ? -1 : 1;
      var digits = tz.slice(1).replace(':', '');
      offMin = sign * (parseInt(digits.slice(0, 2), 10) * 60 + parseInt(digits.slice(2, 4), 10));
    }
    var ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6],
      m[7] ? Math.round(parseFloat('0.' + m[7]) * 1000) : 0);
    if (!isFinite(ms)) return null;
    return {
      ms: ms - offMin * 60000,
      offset: tz || '',
      y: +m[1], mo: +m[2], d: +m[3], hh: +m[4], mm: +m[5], ss: +m[6],
      raw: s
    };
  }
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  // Показываем метку ровно в том поясе, в котором её записала программа,
  // и подписываем это смещение: у админа может быть другой пояс.
  function fmtInstant(s) {
    var p = parseInstant(s);
    if (!p) return s ? String(s) : '—';
    return pad2(p.d) + '.' + pad2(p.mo) + '.' + p.y + ' ' +
      pad2(p.hh) + ':' + pad2(p.mm) + ':' + pad2(p.ss) +
      ' · пояс отчёта ' + (p.offset && p.offset !== 'Z' ? p.offset : 'UTC');
  }
  function fmtAge(s) {
    var p = parseInstant(s);
    if (!p) return null;
    var diff = Date.now() - p.ms;
    var abs = Math.abs(diff);
    var min = 60000, hour = 3600000, day = 86400000;
    var txt;
    if (abs < min) txt = 'меньше минуты';
    else if (abs < hour) txt = Math.round(abs / min) + ' мин';
    else if (abs < day) txt = Math.round(abs / hour) + ' ч';
    else if (abs < day * 31) txt = Math.round(abs / day) + ' сут';
    else txt = Math.round(abs / (day * 30.44)) + ' мес';
    if (diff < 0) return { text: 'метка в будущем на ' + txt, bad: true };
    return { text: txt + ' назад', bad: false };
  }

  function toast(msg) {
    var t = $('toast');
    if (!t) return;
    t.textContent = msg;
    t.classList.add('show');
    if (toast.timer) clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { t.classList.remove('show'); }, 2100);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return legacyCopy(text); });
    }
    return Promise.resolve(legacyCopy(text));
  }
  function legacyCopy(text) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, text.length);
      var ok = document.execCommand && document.execCommand('copy');
      document.body.removeChild(ta);
      return !!ok;
    } catch (e) {
      return false;
    }
  }
  function copyButton(label, value, cls) {
    var b = el('button', 'copy ' + (cls || ''), label);
    b.type = 'button';
    b.title = 'Скопировать';
    b.setAttribute('aria-label', label + ' — скопировать');
    b.addEventListener('click', function () {
      copyText(value).then(function (ok) {
        if (ok) {
          b.classList.add('done');
          toast('Скопировано: ' + (value.length > 46 ? value.slice(0, 43) + '…' : value));
          setTimeout(function () { b.classList.remove('done'); }, 1200);
        } else {
          toast('Браузер не дал буфер обмена — выдели и скопируй вручную');
        }
      });
    });
    return b;
  }

  /* ---------------------------------------------------------------------- доступ
     Только чтение: ни fetch, ни XHR, ни form. Файл идёт в FileReader -> память вкладки. */

  function readFileText(file) {
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onload = function () { resolve(String(fr.result)); };
      fr.onerror = function () { reject(new Error('Файл не прочитан: ' + (file && file.name ? file.name : '?'))); };
      try {
        fr.readAsText(file, 'utf-8'); // TextDecoder снимает BOM; на всякий случай stripBom в CORE
      } catch (e) {
        reject(e);
      }
    });
  }

  var state = {
    items: [],       // {id, name, size, text, outcome, error}
    active: -1,
    filter: { q: '', family: '', min: 'info' },
    rawMode: 'pretty',
    ban: null        // черновик команды бана активного отчёта
  };
  var seq = 0;

  function verdictRuFromReport(report) {
    var v = report && report.result ? report.result.verdict : null;
    return ru(VERDICT_RU, v, v ? String(v) : 'без заключения');
  }

  function intakeError(msg) {
    var box = $('intake-err');
    if (!msg) { box.hidden = true; box.textContent = ''; return; }
    box.hidden = false;
    box.textContent = msg;
  }

  function addFiles(files) {
    var list = Array.prototype.slice.call(files || []);
    if (!list.length) return;
    intakeError(null);
    var jobs = list.map(function (file) {
      return readFileText(file).then(function (text) {
        return { name: file.name || '(без имени)', size: file.size || text.length, text: text };
      }, function (err) {
        return { name: file.name || '(без имени)', size: 0, text: null, error: String(err && err.message ? err.message : err) };
      });
    });
    Promise.all(jobs).then(function (loaded) {
      loaded.forEach(function (item) {
        seq += 1;
        var entry = { id: seq, name: item.name, size: item.size, text: item.text, outcome: null, error: item.error || null };
        state.items.push(entry);
        state.active = state.items.length - 1;
      });
      return resolveAll().then(render);
    }).catch(function (err) {
      intakeError('Не получилось прочитать: ' + (err && err.message ? err.message : err));
    });
  }

  function addText(text, name) {
    seq += 1;
    state.items.push({ id: seq, name: name || 'текст из буфера', size: text.length, text: text, outcome: null, error: null });
    state.active = state.items.length - 1;
    return resolveAll().then(render);
  }

  function resolveAll() {
    var chain = Promise.resolve();
    state.items.forEach(function (item) {
      if (item.error || !item.text) return;
      if (item.outcome && item.outcome.resolved) return;
      chain = chain.then(function () {
        return CORE.verifyText(item.text, verdictRuFromReport).then(function (outcome) {
          outcome.resolved = true;
          item.outcome = outcome;
        }, function (err) {
          item.outcome = {
            resolved: true, intact: false, kind: 'bad_json',
            detail: CORE.MSG.badJsonPrefix + (err && err.message ? err.message : err),
            report: null, payload: null, fileSeal: '', expectedSeal: '', body: item.text
          };
        });
      });
    });
    return chain;
  }

  function activeItem() {
    return state.active >= 0 && state.active < state.items.length ? state.items[state.active] : null;
  }

  /* ------------------------------------------------------------------ рендер рамок */

  function render() {
    renderTabs();
    var work = $('work');
    work.textContent = '';
    var item = activeItem();
    paintActiveChip(item);
    if (!item) {
      work.append(idleCard());
      return;
    }
    if (item.error) {
      work.append(el('div', 'err', 'Файл не прочитан: ' + item.error));
      return;
    }
    var out = item.outcome;
    if (!out) { work.append(idleCard('Идёт разбор файла…')); return; }

    work.append(bannerCard(item, out));
    if (out.report) {
      var report = out.report;
      work.append(verdictCard(item, report, out));
      work.append(banCard(item, report, out));
      work.append(rootsCard(report));
      work.append(settingsCard(report));
      work.append(familiesCard(report));
      work.append(statsCard(report));
      work.append(findingsCard(report));
      work.append(suppressedCard(report));
      work.append(inventoryCard(report));
      work.append(warningsCard(report));
    } else {
      work.append(noPayloadCard(out));
    }
    work.append(humanCard(item, out));
    work.append(rawCard(out));
  }

  /// Чип в шапке: какой отчёт сейчас открыт и цел ли он. Админ держит в
  /// вкладке несколько присланных файлов — без этой строки они различимы
  /// только по заголовку вкладки-таба.
  function paintActiveChip(item) {
    var chip = $('chip-active');
    if (!item) { chip.hidden = true; chip.textContent = ''; chip.className = 'chip'; return; }
    var rep = item.outcome && item.outcome.report;
    var parts = [];
    if (rep && rep.player) parts.push(rep.player);
    if (rep && rep.result) parts.push(ru(VERDICT_RU, rep.result.verdict, '—'));
    if (item.error) parts.push('не прочитан');
    else if (item.outcome && !item.outcome.intact) parts.push('печать не сошлась');
    else if (item.outcome) parts.push('цел');
    else parts.push('разбирается…');
    chip.textContent = parts.join(' · ');
    chip.className = 'chip' + (item.outcome && item.outcome.intact ? ' ok' : (item.error ? ' bad' : ''));
    chip.hidden = false;
  }

  function idleCard(msg) {
    var c = el('section', 'card');
    c.append(el('h2', null, 'Отчёт не загружен'));
    c.append(el('p', 'side-note', msg ||
      'Сканер игрока пишет отчёт в файл .swcc и пересылает его тебе сам — на сервер ничего не уходит. ' +
      'Здесь ты проверяешь присланный файл: целость машиночитаемой части, печать и содержимое находок.'));
    return c;
  }

  /* ------------------------------------------------------------------- banner */

  function bannerCard(item, out) {
    var tone, title, glyph;
    if (out.intact) { tone = 'ok'; title = 'Печать сходится'; glyph = '✓'; }
    else if (out.kind === 'no_payload' || out.kind === 'no_payload_end') { tone = 'part'; title = 'Payload не найден'; glyph = '!'; }
    else if (out.kind === 'no_seal') { tone = 'part'; title = 'Печать в файле отсутствует'; glyph = '!'; }
    else { tone = 'bad'; title = 'Печать НЕ сходится — файл отредактирован'; glyph = '✕'; }

    var b = el('section', 'banner ' + tone);
    b.setAttribute('role', 'status');
    b.setAttribute('aria-live', 'polite');
    var head = el('div', 'head');
    push(head, el('div', 'glyph', glyph), (function () {
      var col = el('div');
      col.append(el('p', 'title', title));
      col.append(el('p', 'detail', out.detail));
      col.append(el('p', 'cli', 'Формулировка совпадает с Report::verify в CLI: ' + out.detail));
      return col;
    })());
    b.append(head);

    var box = el('div', 'sealbox');
    box.append(sealCell('Печать в файле (!SEAL!)', out.fileSeal || 'нет строки печати', out.intact ? 'ok' : 'bad'));
    box.append(sealCell('Пересчитано в браузере', out.expectedSeal || 'н/д (payload не разобран)', out.intact ? 'ok' : 'bad'));
    box.append(sealCell('Payload, длина base64', out.payload ? fmtInt(out.payload.length) + ' симв. (между маркерами, пробелы удалены)' : '—', ''));
    box.append(sealCell('Чем пересчитана печать', engineLabel(out), ''));
    box.append(sealCell('Соль печати', CORE.SEAL_SALT, ''));
    box.append(sealCell('Файл', item.name + ' · ' + fmtBytes(item.size), ''));
    b.append(box);

    var algo = el('p', 'note');
    algo.textContent = 'Печать = контрольная сумма машиночитаемой части с солью "' + CORE.SEAL_SALT + '", ' +
      'первые 24 символа. Она подтверждает только то, что машиночитаемая часть не менялась после ' +
      'формирования отчёта. Она не доказывает авторство: соль лежит в программе игрока.';
    b.append(algo);

    if (!out.intact && out.report) {
      var w = el('p', 'note bad');
      w.textContent = 'Payload при этом разобрался: ниже показано содержимое файла так, как оно прочитано. ' +
        'Сверяй с игроком поштучно — такому отчёту доверять нельзя.';
      b.append(w);
    }
    return b;
  }

  function engineLabel(out) {
    if (out.hashEngine === 'webcrypto') return 'браузерный движок (crypto.subtle)';
    if (out.hashEngine === 'local-sha256') {
      return 'встроенная реализация страницы (браузерный движок тут недоступен)';
    }
    return CORE.subtleAvailable() ? 'браузерный движок (crypto.subtle)' : 'встроенная реализация страницы';
  }

  function sealCell(k, v, cls) {
    var cell = el('div', 'sealcell');
    cell.append(el('div', 'k', k));
    cell.append(el('div', 'v ' + (cls || ''), v));
    return cell;
  }

  function noPayloadCard(out) {
    var c = el('section', 'card');
    c.append(el('h2', null, 'Разбор'));
    var p = el('p', 'note bad');
    if (out.kind === 'bad_base64') {
      p.textContent = 'Машиночитаемая часть между маркерами есть, но не декодируется как base64. ' +
        'Обычно это значит, что файл правили текстовым редактором или он обрезался при пересылке.';
    } else if (out.kind === 'bad_json') {
      p.textContent = 'Base64 декодировался, но содержимое не является JSON отчёта. ' +
        'Файл подменён или повреждён. Проверка: ' + out.detail;
    } else {
      p.textContent = 'Покажи игроку этот файл целиком и попроси пересохранить отчёт в программе, ' +
        'а не копировать текст в Discord: в тексте нет машиночитаемой части, её нельзя проверить.';
    }
    c.append(p);
    // Шаблон команды нужен и здесь: иногда админ решает по другим материалам,
    // а содержимое файла в этот раз прочесть нельзя.
    var tpl = el('div', 'ban-cmd');
    var tplCode = el('code');
    tplCode.textContent = banText({ nick: '', duration: '', reason: '' });
    var tplCopy = el('button', 'btn sm', 'Скопировать шаблон');
    tplCopy.type = 'button';
    tplCopy.addEventListener('click', function () {
      copyText(banText({ nick: '', duration: '', reason: '' })).then(function (ok) {
        toast(ok ? 'Шаблон скопирован' : 'Браузер не дал буфер обмена');
      });
    });
    push(tpl, tplCode, tplCopy);
    c.append(tpl);
    var pre = el('pre', 'excerpt');
    pre.textContent = headSnippet(out.body || '', 1400);
    c.append(el('p', 'note', 'Начало файла (первые 1400 симв.), чтобы понять, что именно пришло:'));
    c.append(pre);
    return c;
  }

  function headSnippet(s, n) {
    return s.length > n ? s.slice(0, n) + '\n…(дальше не показано)' : s;
  }

  /* ------------------------------------------------------------------ verdict */

  function verdictCard(item, report, out) {
    var res = report.result || {};
    var tone = VERDICT_TONE[res.verdict] || 'info';
    var c = el('section', 'card');

    var head = el('div', 'vhead');
    var left = el('div');
    left.append(el('h2', 'vbig sev-' + tone, 'Заключение: ' + ru(VERDICT_RU, res.verdict, '—')));
    left.append(el('div', 'vsub',
      'Отчёт ' + (report.id || '—') + ' · игрок ' + (report.player || 'ник не указан') +
      ' · формат ' + (report.format || '—') +
      ' · приложение swcc ' + (report.app_version || '—') +
      ' · база сигнатур ' + (res.db_version || '—')));
    head.append(left);

    var score = Number(res.score || 0);
    var sc = el('div', 'score');
    sc.append(el('div', 'num sev-' + tone, fmtInt(score)));
    sc.append(el('div', 'lbl', 'балл риска'));
    head.append(sc);
    c.append(head);

    var bar = el('div', 'bar');
    var fill = el('i', 'bg-' + tone);
    fill.style.width = Math.max(2, Math.min(100, score)) + '%';
    bar.append(fill);
    c.append(bar);
    c.append(el('p', 'note', 'Шкала 0-100+; больше 80 — высокая вероятность. Балл складывается из весов находок ' +
      'и их уверенности, поэтому он не «процент вины».'));

    var advice = el('p', 'advice');
    advice.textContent = 'Что это значит: ' + (VERDICT_ADVICE[res.verdict] || 'нет поясствия для этого заключения.');
    c.append(advice);

    // Разбивка находок — та же, что в counts() у Report::render
    var findings = res.findings || [];
    var bySev = {};
    findings.forEach(function (f) { bySev[f.severity] = (bySev[f.severity] || 0) + 1; });
    var counts = el('div', 'counts');
    counts.append(cnt('всего находок', findings.length, null));
    SEVERITY_LEVELS.forEach(function (s) {
      counts.append(cnt(SEVERITY_RU[s], bySev[s] || 0, s));
    });
    counts.append(cnt('отброшено как легитимное', (res.suppressed || []).length, ''));
    counts.append(cnt('файлов в mods/addons', (res.mods || []).length, ''));
    c.append(counts);

    var created = report.created_at;
    var age = fmtAge(created);
    var grid = el('div', 'kv');
    push(grid,
      kvItem('Время формирования', fmtInstant(created) + (age ? ' · ' + age.text : '')),
      kvItem('Начало обхода', fmtInstant(res.started_at)),
      kvItem('Игрок (учётка ПК)', (res.environment && res.environment.user) || '—'),
      kvItem('Ник из ввода игрока', report.player || 'не указан (старая версия swcc)'),
      kvItem('Ник из строки запуска', (res.environment && res.environment.nick_from_launch) || 'не определён'),
      kvItem('ОС / архитектура', (res.environment && res.environment.os) || '—'),
      kvItem('Часовой пояс', (res.environment && res.environment.timezone) || '—'),
      kvItem('Версии игры', res.environment && res.environment.mc_versions && res.environment.mc_versions.length
        ? res.environment.mc_versions.join(', ') : 'не определены'),
      kvItem('Java из лога', (res.environment && res.environment.java_from_log) || 'не найдено'),
      kvItem('Загрузчик из лога', (res.environment && res.environment.loader_from_log) || 'не найдено'),
      kvItem('Согласие игрока', agreementText(report)),
      kvItem('Источники базы сигнатур', (res.db_sources || []).join('; ') || '—')
    );
    c.append(grid);

    var sent = el('p', 'note');
    sent.textContent = 'Отправлено на сервер: НЕТ. Отчёт создаётся локально и никуда не уходит; ' +
      'игрок пересылает файл сам.';
    c.append(sent);

    var actions = el('div', 'bar');
    actions.style.paddingTop = '12px';
    var tSum = el('button', 'btn sm', 'Скопировать сводку для тикета');
    tSum.type = 'button';
    tSum.title = 'Клавиша C';
    tSum.addEventListener('click', function () {
      copyText(summaryForTicket(item, report)).then(function (ok) {
        toast(ok ? 'Сводка скопирована' : 'Браузер не дал буфер обмена');
      });
    });
    var tJump = el('button', 'btn sm ghost', 'К находкам');
    tJump.type = 'button';
    tJump.addEventListener('click', function () {
      var f = $('f-q');
      if (f) { f.focus(); f.scrollIntoView({ block: 'center' }); }
    });
    push(actions, tSum, tJump);
    c.append(actions);

    if (!out.intact) {
      var warn = el('p', 'note bad');
      warn.textContent = 'Внимание: печать не подтверждена — всё ниже прочитано из файла, которому нельзя доверять.';
      c.append(warn);
    }
    return c;
  }

  function cnt(label, n, sev) {
    var b = el('span', 'cnt');
    b.append(el('span', null, label + ' '));
    b.append(el('b', sev ? 'sev-' + sev : null, fmtInt(n)));
    return b;
  }

  /* --------------------------------------------------------------- бан-строка */

  function banCard(item, report, out) {
    if (!state.ban || state.ban.key !== item.id) state.ban = banDraft(report, out);
    var d = state.ban;

    var c = el('section', 'card ban');
    var h = el('h2');
    h.append(el('span', null, 'Команда бана'));
    h.append(el('span', 'n', ru(VERDICT_RU, (report.result || {}).verdict, '—')));
    c.append(h);
    c.append(el('p', 'hint', 'Шаблон /ban <ник> <длительность> <причина> — заполняется из отчёта, но правится вручную: ' +
      'решение и формулировка причины остаются за админом.'));

    var box = el('div', 'ban-cmd');
    var code = el('code');
    var copy = el('button', 'btn sm primary', 'Скопировать команду');
    copy.type = 'button';
    function paint() {
      code.textContent = '';
      code.append(document.createTextNode('/ban '));
      code.append(arg(d.nick, '<ник>'));
      code.append(document.createTextNode(' '));
      code.append(arg(d.duration, '<длительность>'));
      code.append(document.createTextNode(' '));
      code.append(arg(d.reason, '<причина>'));
      box.setAttribute('aria-label', banText(d));
    }
    function arg(v, ph) {
      var s = el('span', 'arg');
      s.textContent = (v === null || v === undefined || v === '') ? ph : String(v);
      return s;
    }
    copy.addEventListener('click', function () {
      copyText(banText(d)).then(function (ok) {
        toast(ok ? 'Команда скопирована' : 'Браузер не дал буфер обмена — выдели строку вручную');
      });
    });
    push(box, code, copy);
    c.append(box);

    var fields = el('div', 'ban-fields');
    push(fields,
      field('ban-nick', 'Ник игрока', 'text', d.nick, 'Steve_93', function (v) { d.nick = v; paint(); }),
      field('ban-duration', 'Длительность', 'text', d.duration, '7d', function (v) { d.duration = v; paint(); paintPresets(); }),
      taField('ban-reason', 'Причина', d.reason, 'Читы: Meteor Client · отчёт SWCC-…', function (v) { d.reason = v; paint(); })
    );
    c.append(fields);

    var presets = el('div', 'presets');
    presets.append(el('span', 'lb', 'длительность'));
    var presButtons = [];
    BAN_PRESETS.forEach(function (p) {
      var b = el('button', 'pre', p);
      b.type = 'button';
      b.addEventListener('click', function () {
        d.duration = p;
        var f = $('ban-duration');
        if (f) f.value = p;
        paintPresets();
        paint();
      });
      presButtons.push([b, p]);
      presets.append(b);
    });
    c.append(presets);
    function paintPresets() {
      presButtons.forEach(function (pair) {
        pair[0].setAttribute('aria-pressed', pair[1] === d.duration ? 'true' : 'false');
      });
    }

    var res = report.result || {};
    if (!d.nick) {
      c.append(el('p', 'note warn', 'В отчёте нет ника: его вводит игрок в программе, начиная с версии swcc 0.1.0. ' +
        'Допиши вручную — по учётке Windows команду составлять нельзя.'));
    }
    if (res.verdict === 'clean' || res.verdict === 'no_data' || res.verdict === 'low_signal') {
      c.append(el('p', 'note', 'По этому заключению бан не обоснован: ' +
        (VERDICT_ADVICE[res.verdict] || 'случай единичный.') +
        ' Строка показана на случай, если решение принято по другим материалам.'));
    }
    if (!out.intact) {
      c.append(el('p', 'note bad', 'Печать этого отчёта не сошлась — содержимому файла доверять нельзя, ' +
        'и причина в команде это отмечает.'));
    }

    paint();
    paintPresets();
    return c;
  }

  function field(id, label, type, value, ph, oninput) {
    var f = el('div', 'fld');
    var l = el('label', null, label);
    l.setAttribute('for', id);
    var i = el('input');
    i.type = type;
    i.id = id;
    i.value = value || '';
    i.placeholder = ph;
    i.addEventListener('input', function () { oninput(i.value.trim()); });
    f.append(l, i);
    return f;
  }

  function taField(id, label, value, ph, oninput) {
    var f = el('div', 'fld');
    f.style.gridColumn = '1 / -1';
    var l = el('label', null, label);
    l.setAttribute('for', id);
    var t = el('textarea');
    t.id = id;
    t.value = value || '';
    t.placeholder = ph;
    t.rows = 2;
    t.addEventListener('input', function () { oninput(t.value.trim()); });
    f.append(l, t);
    return f;
  }
  function kvItem(k, v, cls) {
    var i = el('div', 'kv-item');
    i.append(el('div', 'kv-k', k));
    i.append(el('div', 'kv-v ' + (cls || ''), v === '' || v === null || v === undefined ? '—' : v));
    return i;
  }
  function agreementText(report) {
    var a = report.agreement || {};
    if (a.accepted === true) {
      return 'принято ' + fmtInstant(a.accepted_at) + ' (текст ' + (a.text_version || '—') + ')';
    }
    if (a.accepted === false) return 'НЕ принято — проверка не выполнялась';
    return a.accepted === undefined ? '—' : 'нет записи о согласии';
  }

  /* -------------------------------------------------------------------- roots */

  function rootsCard(report) {
    var c = el('section', 'card');
    c.append(el('h2', null, 'Что сканировалось'));
    var roots = report.roots || [];
    if (!roots.length) {
      c.append(el('p', 'empty', 'Ни одна папка игры не найдена — проверка не выполнялась.'));
      return c;
    }
    var list = el('ul', 'ticks');
    roots.forEach(function (r) {
      var li = el('li', 'mono');
      li.append(el('span', 't', '▪'));
      var body = el('span', 'b');
      body.textContent = '[' + ru(ROOT_KIND_RU, r.kind, r.kind || '—') + '] ' + (r.label || '—') + ' — ' + dispPath(r.path);
      li.append(body);
      list.append(li);
    });
    c.append(list);
    c.append(el('p', 'note', 'Исключены из обхода: assets, libraries, runtime, bin, каталоги нативок ' +
      '(легитимные и огромные).'));
    return c;
  }

  /* ---------------------------------------------------------------- settings */

  function settingsCard(report) {
    var c = el('section', 'card');
    c.append(el('h2', null, 'Параметры проверки'));
    var list = report.settings || [];
    if (!list.length) {
      c.append(el('p', 'empty', 'Отчёт сформирован версией swcc до появления настроек: профиль обхода не записан. ' +
        'Считай, что проверка была полной по умолчанию, и уточняйте это у игрока.'));
      return c;
    }
    var ul = el('ul', 'ticks');
    list.forEach(function (s) {
      var li = el('li');
      li.append(el('span', 't', '▪'));
      var b = el('span', 'b');
      b.textContent = String(s);
      li.append(b);
      ul.append(li);
    });
    c.append(ul);
    c.append(el('p', 'note', 'Настройки выбирает игрок перед проверкой. Если чтение содержимого или разбор архивов ' +
      'были выключены, часть признаков просто не могла быть найдена — это «не досмотрено», а не «чисто».'));
    return c;
  }

  /// Верbatim-префикс Windows (\\?\) в путях — служебный шум: читаемому виду
  /// он только мешает, а значение пути не меняет.
  function dispPath(p) {
    var s = String(p === null || p === undefined ? '—' : p);
    if (s.slice(0, 4) === '\\\\?\\') s = s.slice(4);
    return s || '—';
  }

  /* ----------------------------------------------------------------- families */

  function familiesCard(report) {
    var fams = (report.result && report.result.families) || [];
    var c = el('section', 'card');
    c.append(el('h2', null, 'Семейства'));
    c.append(el('p', 'hint', 'Группировка находок по семейству: подтверждение несколькими независимыми файлами ' +
      'весомее одиночного совпадения.'));
    if (!fams.length) { c.append(el('p', 'empty', 'Ни одного семейства.')); return c; }
    var sorted = fams.slice().sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    var tbl = el('div', 'tbl-scroll');
    var t = el('table');
    var thead = el('thead');
    var hrow = el('tr');
    ['Семейство', 'Тип', 'Уровень', 'Находок', 'Файлов', 'Подтверждено', 'Вклад', 'Макс. уверенность'].forEach(function (x) {
      hrow.append(el('th', null, x));
    });
    thead.append(hrow);
    t.append(thead);
    var tb = el('tbody');
    sorted.forEach(function (f) {
      var tr = el('tr');
      var sev = f.severity in SEVERITY_RU ? f.severity : 'info';
      var sevCell = el('td');
      sevCell.append(el('span', 'sev-' + sev, SEVERITY_RU[sev]));
      push(tr,
        td(f.family || '—', 'p'),
        td(ru(KIND_RU, f.kind)),
        sevCell,
        tdNum(f.findings), tdNum(f.distinct_files),
        td(f.corroborated ? 'да — несколько независимых' : 'нет'),
        tdNum(f.score),
        tdNum(fmtPct(f.max_confidence))
      );
      tb.append(tr);
    });
    t.append(tb);
    tbl.append(t);
    c.append(tbl);
    return c;
  }
  function td(value, cls) {
    var d = el('td', cls || null);
    d.textContent = value === null || value === undefined ? '—' : String(value);
    return d;
  }
  function tdNum(v) { return el('td', 'num', fmtInt(v)); }

  /* -------------------------------------------------------------------- stats */

  function statsCard(report) {
    var st = (report.result && report.result.stats) || {};
    var c = el('section', 'card');
    c.append(el('h2', null, 'Статистика обхода и пределы'));
    var grid = el('div', 'kv');
    push(grid,
      kvItem('Файлов просмотрено', fmtInt(st.files_walked)),
      kvItem('Каталогов пройдено', fmtInt(st.dirs_walked)),
      kvItem('Прочитано байт', fmtBytes(st.bytes_read)),
      kvItem('Архивов открыто', fmtInt(st.archives_opened)),
      kvItem('Архивов распаковано глубоко', fmtInt(st.archives_deep_scanned)),
      kvItem('Архивов пропущено по бюджету', fmtInt(st.archives_skipped_by_budget)),
      kvItem('Системных каталогов пропущено', fmtInt(st.dirs_pruned_system)),
      kvItem('Файлов слишком больших', fmtInt(st.files_too_large)),
      kvItem('Файлов не читалось', fmtInt(st.files_unreadable)),
      kvItem('Симлинков пропущено', fmtInt(st.symlinks_skipped)),
      kvItem('Отброшено как легитимное', plural(st.suppressed, 'совпадение', 'совпадения', 'совпадений')),
      kvItem('Длительность', fmtInt(st.duration_ms) + ' мс')
    );
    c.append(grid);

    var flags = [];
    if (st.walk_limited) flags.push('ВНИМАНИЕ: обход достиг лимита числа файлов — часть файлов не проверена.');
    if (st.aborted) flags.push('ВНИМАНИЕ: проверка прервана пользователем — вывод неполный.');
    if ((st.archives_skipped_by_budget || 0) > 0) {
      flags.push('Архивов не распаковано из-за бюджета: ' + fmtInt(st.archives_skipped_by_budget) +
        ' — содержимое этих архивов не проверялось.');
    }
    if ((st.files_too_large || 0) > 0 || (st.files_unreadable || 0) > 0) {
      flags.push('Часть файлов не открывалась на содержимое (крупнее лимита или не читалась): ' +
        fmtInt(st.files_too_large) + ' + ' + fmtInt(st.files_unreadable) + ' — проверены только по имени и метаданным.');
    }
    if (!flags.length) {
      c.append(el('p', 'note', 'Лимиты обхода и бюджеты не достигнуты: проверено всё, что нашлось в корнях.'));
    } else {
      var ul = el('ul', 'ticks');
      flags.forEach(function (f) {
        var li = el('li');
        li.append(el('span', 't sev-medium', '⚠'));
        li.append(el('span', 'b', f));
        ul.append(li);
      });
      c.append(ul);
      c.append(el('p', 'note warn', 'Неполный обход — это не «чисто»: это «не досмотрено».'));
    }
    return c;
  }

  /* ----------------------------------------------------------------- findings */

  function findingsCard(report) {
    var all = (report.result && report.result.findings) || [];
    var c = el('section', 'card');
    var title = el('h2');
    title.append(el('span', null, 'Находки'));
    var titleCount = el('span', 'n', '0 из ' + all.length);
    title.append(titleCount);
    c.append(title);

    var fams = [];
    var seen = {};
    all.forEach(function (f) {
      var k = f.family || '—';
      if (!seen[k]) { seen[k] = 1; fams.push(k); }
    });
    fams.sort();

    var filters = el('div', 'filters');
    var qField = el('div', 'fld');
    var qLabel = el('label', null, 'Поиск по подстроке');
    var q = el('input');
    q.type = 'search';
    q.id = 'f-q';
    q.placeholder = 'ник, Meteor, mods/, путь…';
    q.setAttribute('aria-label', qLabel.textContent);
    q.value = state.filter.q;
    push(qField, qLabel, q);

    var minField = el('div', 'fld');
    var minLabel = el('label', null, 'Уровень не ниже');
    var min = el('select');
    min.id = 'f-min';
    [['info', 'все'], ['low', 'низкая'], ['medium', 'средняя'], ['high', 'высокая'], ['critical', 'критическая']]
      .forEach(function (pair) {
        var o = el('option', null, pair[1]);
        o.value = pair[0];
        if (state.filter.min === pair[0]) o.selected = true;
        min.append(o);
      });
    minLabel.setAttribute('for', 'f-min');
    push(minField, minLabel, min);

    var famField = el('div', 'fld');
    var famLabel = el('label', null, 'Семейство');
    var fam = el('select');
    fam.id = 'f-fam';
    var any = el('option', null, 'любое');
    any.value = '';
    fam.append(any);
    fams.forEach(function (name) {
      var o = el('option', null, name);
      o.value = name;
      if (state.filter.family === name) o.selected = true;
      fam.append(o);
    });
    famLabel.setAttribute('for', 'f-fam');
    push(famField, famLabel, fam);

    var shown = el('div', 'shown', '');
    var reset = el('button', 'btn sm ghost', 'Сбросить');
    reset.type = 'button';
    reset.addEventListener('click', function () {
      state.filter = { q: '', family: '', min: 'info' };
      q.value = ''; fam.value = ''; min.value = 'info';
      apply();
    });
    push(filters, qField, minField, famField, reset, shown);
    c.append(filters);
    c.append(el('p', 'hint', 'Как и запрос в программе (scanner::query): подстрока ищется по семейству, сигнатуре, ' +
      'пути, сути, способу проверки, типу и уровню, плюс по признакам.'));

    var list = el('div', 'findings');
    list.id = 'f-list';
    list.setAttribute('role', 'list');
    c.append(list);

    function apply() {
      state.filter.q = q.value;
      state.filter.min = min.value;
      state.filter.family = fam.value;
      var kept = all.filter(function (f) {
        if (rankOf(f.severity) < rankOf(state.filter.min)) return false;
        if (state.filter.family && (f.family || '—') !== state.filter.family) return false;
        return matchesQuery(f, state.filter.q);
      });
      // порядок как в Report::render: уровень, затем уверенность
      kept.sort(function (a, b) {
        var d = rankOf(b.severity) - rankOf(a.severity);
        if (d) return d;
        return (Number(b.confidence) || 0) - (Number(a.confidence) || 0);
      });
      list.textContent = '';
      if (!kept.length) {
        list.append(el('p', 'empty', all.length
          ? 'Под фильтр не попала ни одна находка.'
          : 'Ни одной находки. См. «Пределы метода»: чистый отчёт не равен честной игре.'));
      } else {
        kept.forEach(function (f, i) { list.append(findingCard(f, i + 1)); });
      }
      titleCount.textContent = kept.length + ' из ' + all.length;
      shown.textContent = 'показано ' + kept.length + ' из ' + all.length;
    }

    q.addEventListener('input', apply);
    min.addEventListener('change', apply);
    fam.addEventListener('change', apply);
    apply();
    return c;
  }

  function rankOf(sev) {
    var r = SEVERITY_RANK[sev];
    return r === undefined ? 0 : r;
  }

  function matchesQuery(f, raw) {
    var needle = String(raw || '').trim().toLowerCase();
    if (!needle) return true;
    var hay = [
      f.family, f.sig_id, locationOf(f), f.explain, f.verify,
      ru(KIND_RU, f.kind), SEVERITY_RU[f.severity] || String(f.severity || '')
    ];
    var ev = f.evidence || {};
    if (ev.root) hay.push(ev.root);
    if (ev.source) hay.push(ev.source);
    if (ev.referenced_file) hay.push(ev.referenced_file);
    (f.rules || []).forEach(function (r) {
      hay.push(r.detail);
      hay.push(RULE_RU[r.rule] || r.rule);
    });
    for (var i = 0; i < hay.length; i++) {
      if (hay[i] && String(hay[i]).toLowerCase().indexOf(needle) >= 0) return true;
    }
    return false;
  }

  function locationOf(f) {
    var ev = f.evidence || {};
    if (ev.type === 'file' || (ev.rel_path !== undefined && ev.size_bytes !== undefined)) return ev.rel_path || '';
    if (ev.type === 'directory') return (ev.rel_path || '') + '/';
    if (ev.type === 'launch_line') return ev.source || '';
    return ev.rel_path || ev.source || '';
  }

  function findingCard(f, index) {
    var sev = f.severity in SEVERITY_RU ? f.severity : 'info';
    var c = el('article', 'fcard sev-' + sev);
    c.setAttribute('role', 'listitem');

    var head = el('div', 'fhead');
    head.append(el('span', 'fid', '[F-' + pad2(index) + ']'));
    head.append(el('span', 'badge sev-' + sev, SEVERITY_RU[sev]));
    head.append(el('span', 'ffam', f.family || '—'));
    head.append(el('span', 'fkind', ru(KIND_RU, f.kind)));
    head.append(el('span', 'fsig', f.sig_id || '—'));
    var meta = el('div', 'fmeta');
    meta.append(el('span', 'pill', 'уверенность ' + fmtPct(f.confidence)));
    meta.append(el('span', 'pill', 'вес ' + fmtInt(f.weight)));
    var eff = Math.round((Number(f.weight) || 0) * (Number(f.confidence) || 0));
    meta.append(el('span', 'pill', 'вклад ' + fmtInt(eff)));
    head.append(meta);
    c.append(head);

    var body = el('div', 'fbody');
    var ev = f.evidence || {};
    if (ev.type === 'file' || (typeof ev.rel_path === 'string' && typeof ev.size_bytes !== 'undefined')) {
      body.append(cell('Файл', ev.rel_path, 'mono'));
      body.append(cell('Где', ev.root));
      body.append(cell('Размер', fmtBytes(ev.size_bytes)));
      body.append(mtimeCell(ev.modified));
      body.append(askCell(ev.root, ev.rel_path));
    } else if (ev.type === 'directory' || (typeof ev.rel_path === 'string' && typeof ev.size_bytes === 'undefined')) {
      body.append(cell('Каталог', (ev.rel_path || '') + '/', 'mono'));
      body.append(cell('Где', ev.root));
    } else if (ev.type === 'launch_line') {
      body.append(cell('Источник', ev.source, 'mono'));
      if (ev.referenced_file) body.append(cell('Названный файл', ev.referenced_file, 'mono'));
    } else if (ev.type) {
      body.append(cell('Доказательство', 'неизвестный тип: ' + ev.type, 'mono'));
    }
    c.append(body);

    if (ev.type === 'launch_line') {
      var block = el('div', 'prose');
      var wrap = el('div');
      wrap.append(el('div', 'pk', 'Строка запуска'));
      var pre = el('pre', 'excerpt');
      pre.textContent = ev.excerpt || '';
      wrap.append(pre);
      block.append(wrap);
      c.append(block);
    }

    var rules = f.rules || [];
    if (rules.length) {
      c.append(el('div', 'sub-k', 'Признаки:'));
      var rl = el('ul', 'rules');
      rules.forEach(function (r) {
        var li = el('li');
        li.append(el('span', 'rk', RULE_RU[r.rule] || r.rule || '—'));
        var detail = el('span', 'rd');
        detail.textContent = String(r.detail || '').slice(0, 400);
        li.append(detail);
        if (typeof r.confidence === 'number') li.append(el('span', 'rc', fmtPct(r.confidence)));
        rl.append(li);
      });
      c.append(rl);
    }

    var prose = el('div', 'prose');
    if (f.explain) prose.append(proseBlock('Суть', f.explain, ''));
    if (f.verify) prose.append(proseBlock('Как проверить', f.verify, 'verify'));
    if (prose.childNodes.length) c.append(prose);
    return c;
  }

  function cell(k, v, cls) {
    var d = el('div', 'fcell');
    d.append(el('div', 'k', k));
    var val = el('div', 'v ' + (cls || ''));
    val.textContent = (v === null || v === undefined || v === '') ? '—' : String(v);
    d.append(val);
    return d;
  }

  function mtimeCell(m) {
    var d = el('div', 'fcell');
    d.append(el('div', 'k', 'Изменён'));
    var val = el('div', 'v mono');
    var age = fmtAge(m);
    val.textContent = m ? fmtInstant(m) : '—';
    d.append(val);
    if (age) {
      var sub = el('div', 'v ' + (age.bad ? 'sev-critical' : ''));
      sub.style.fontSize = '11.5px';
      sub.textContent = age.text;
      d.append(sub);
    }
    return d;
  }

  /// То, о чём просят игрока: путь внутри папки игры. Копируется одним кликом,
  /// чтобы запрос в Discord не собирать вручную из окон.
  function askCell(rootLabel, relPath) {
    var d = el('div', 'fcell');
    d.style.gridColumn = '1 / -1';
    d.append(el('div', 'k', 'Что запросить у игрока'));
    var full = (rootLabel ? rootLabel + ' → ' : '') + (relPath || '—');
    d.append(copyButton(full, relPath || ''));
    var tip = el('div', 'v');
    tip.style.color = 'var(--dim)';
    tip.style.fontSize = '11.5px';
    tip.style.marginTop = '3px';
    tip.textContent = 'Клик — скопировать путь. Присланный по этому пути файл сверь с официальным релизом: ' +
      'пересобранный jar под именем легитимного мода — главный приём маскировки.';
    d.append(tip);
    return d;
  }

  function proseBlock(k, t, cls) {
    var d = el('div');
    d.append(el('div', 'pk', k));
    var body = el('div', 'pt ' + (cls || ''));
    body.textContent = t;
    d.append(body);
    return d;
  }

  /* --------------------------------------------------------------- suppressed */

  function suppressedCard(report) {
    var list = (report.result && report.result.suppressed) || [];
    var c = el('section', 'card');
    var h = el('h2');
    h.append(el('span', null, 'Отброшено как легитимное'));
    h.append(el('span', 'n', String(list.length)));
    c.append(h);
    c.append(el('p', 'hint', 'Совпадение с сигнатурой, которое правило-исключение признало легитимным. ' +
      'Показываем, чтобы админ видел, что именно сканер «спустил».'));
    if (!list.length) { c.append(el('p', 'empty', 'Нет.')); return c; }
    var wrap = el('ul', 'ticks');
    list.forEach(function (s) {
      var li = el('li', 'mono');
      li.append(el('span', 't', '▪'));
      var b = el('span', 'b');
      b.textContent = (s.sig_id || '—') + ' -> ' + (s.path || '—');
      li.append(b);
      var why = el('span', 'b');
      why.style.color = 'var(--muted)';
      why.textContent = '  (' + (s.by || '—') + ')';
      li.append(why);
      wrap.append(li);
    });
    c.append(wrap);
    return c;
  }

  /* ------------------------------------------------------------- inventory */

  function inventoryCard(report) {
    var res = report.result || {};
    var c = el('section', 'card');
    var mods = res.mods || [], packs = res.resource_packs || [];
    var h = el('h2');
    h.append(el('span', null, 'Инвентарь'));
    h.append(el('span', 'n', mods.length + ' mods · ' + packs.length + ' ресурспаков'));
    c.append(h);
    if (!mods.length && !packs.length) {
      c.append(el('p', 'empty', 'Папок mods не найдено или они пусты.'));
      return c;
    }
    if (mods.length) c.append(inventoryTable('Файлы в mods/addons (в порядке обхода)', mods));
    if (packs.length) {
      c.append(el('div', 'note', 'Ресурспаки:'));
      c.append(inventoryTable('Ресурспаки', packs));
    }
    c.append(el('p', 'note', 'Список построен по тому, что сканер нашёл в mods/ и resourcepacks/: имя, путь и ' +
      'размер. Если семейство или путь незнакомы — это повод запросить файл у игрока, а не готовый приговор.'));
    return c;
  }

  function inventoryTable(caption, entries) {
    var wrap = el('div', 'tbl-scroll');
    var t = el('table');
    var head = el('tr');
    ['Название', 'Путь', 'Размер'].forEach(function (x) { head.append(el('th', null, x)); });
    var thead = el('thead');
    thead.append(head);
    t.append(thead);
    var tb = el('tbody');
    entries.forEach(function (m) {
      var tr = el('tr');
      tr.append(el('td', null, m.name || '—'));
      tr.append(el('td', 'p', m.rel_path || '—'));
      tr.append(el('td', 'num', fmtBytes(m.size_bytes)));
      tb.append(tr);
    });
    t.append(tb);
    t.prepend(el('caption', null, caption + ' — ' + entries.length));
    wrap.append(t);
    return wrap;
  }

  /* -------------------------------------------------------------- warnings */

  function warningsCard(report) {
    var res = report.result || {};
    var list = (res.warnings || []).concat(res.db_warnings || []);
    var c = el('section', 'card');
    var h = el('h2');
    h.append(el('span', null, 'Предупреждения'));
    h.append(el('span', 'n', String(list.length)));
    c.append(h);
    if (!list.length) { c.append(el('p', 'empty', 'Нет.')); return c; }
    var ul = el('ul', 'ticks');
    list.forEach(function (w) {
      var li = el('li');
      li.append(el('span', 't sev-medium', '⚠'));
      li.append(el('span', 'b', String(w)));
      ul.append(li);
    });
    c.append(ul);
    return c;
  }

  /* ------------------------------------------------------- human text + raw */

  function humanCard(item, out) {
    var text = stripHuman(out.body || '');
    var d = el('details', 'box');
    var s = el('summary');
    s.append(el('span', null, 'Человекочитаемая часть файла'));
    d.append(s);
    var inner = el('div', 'inner');
    var bar = el('div', 'bar');
    bar.append(el('span', 'note', 'Не является доказательством: печать считается только по payload. ' +
      'Этот текст игрок может отредактировать без поломки печати — заключение всегда бери из машиночитаемой части.'));
    var copy = el('button', 'btn sm', 'Скопировать текст');
    copy.type = 'button';
    copy.addEventListener('click', function () {
      copyText(text).then(function (ok) { toast(ok ? 'Текст скопирован' : 'Браузер не дал буфер обмена'); });
    });
    bar.append(copy);
    inner.append(bar);
    var pre = el('pre', 'out');
    pre.textContent = text ? text : '(пусто)';
    inner.append(pre);
    d.append(inner);
    return d;
  }

  function stripHuman(body) {
    var i = body.indexOf(CORE.PAYLOAD_START);
    if (i < 0) return body;
    var j = body.indexOf(CORE.SEAL_MARKER, i);
    var tail = '';
    if (j >= 0) {
      var nl = body.indexOf('\n', j);
      tail = nl >= 0 ? body.slice(nl + 1) : '';
    }
    return body.slice(0, i) + '…[машиночитаемая часть опущена]…\n' + tail;
  }

  function rawCard(out) {
    var d = el('details', 'box');
    d.id = 'rawbox';
    var s = el('summary');
    s.append(el('span', null, 'Машиночитаемая часть: JSON payload'));
    d.append(s);
    var inner = el('div', 'inner');
    var bar = el('div', 'bar');
    var btnPretty = el('button', 'btn sm' + (state.rawMode === 'pretty' ? ' primary' : ''), 'Отформатированный');
    var btnRaw = el('button', 'btn sm' + (state.rawMode === 'raw' ? ' primary' : ''), 'Как в файле (одной строкой)');
    var btnCopy = el('button', 'btn sm', 'Скопировать JSON');
    btnPretty.type = 'button'; btnRaw.type = 'button'; btnCopy.type = 'button';
    var pre = el('pre', 'out');
    function paint() {
      pre.textContent = out.rawJsonText ? (state.rawMode === 'pretty' ? prettyJson(out.rawJsonText) : out.rawJsonText)
        : '(payload не разобран)';
      btnPretty.className = 'btn sm' + (state.rawMode === 'pretty' ? ' primary' : '');
      btnRaw.className = 'btn sm' + (state.rawMode === 'raw' ? ' primary' : '');
    }
    btnPretty.addEventListener('click', function () { state.rawMode = 'pretty'; paint(); });
    btnRaw.addEventListener('click', function () { state.rawMode = 'raw'; paint(); });
    btnCopy.addEventListener('click', function () {
      copyText(out.rawJsonText || '').then(function (ok) { toast(ok ? 'JSON скопирован' : 'Браузер не дал буфер обмена'); });
    });
    bar.append(btnPretty, btnRaw, btnCopy);
    bar.append(el('span', 'note', 'Декодировано из base64 через TextDecoder("utf-8"): это ровно те байты, ' +
      'которые лежат между маркерами.'));
    inner.append(bar);
    inner.append(pre);
    d.append(inner);
    paint();
    return d;
  }

  function prettyJson(text) {
    try { return JSON.stringify(JSON.parse(text), null, 2); }
    catch (e) { return text; }
  }

  function summaryForTicket(item, report) {
    var res = report.result || {};
    var lines = [
      'Отчёт ' + report.id,
      'Заключение: ' + ru(VERDICT_RU, res.verdict) + ' (балл ' + (res.score || 0) + ')',
      'Приложение: swcc ' + report.app_version + ', база ' + (res.db_version || '—'),
      'Сформирован: ' + report.created_at,
      'Игрок: ' + (report.player || 'ник не указан') +
        ' · учётка ПК: ' + ((res.environment && res.environment.user) || '—') +
        ' · ОС: ' + ((res.environment && res.environment.os) || '—'),
      'Параметры: ' + ((report.settings || []).join(' · ') || 'не записаны'),
      'Печать: ' + (item.outcome && item.outcome.intact ? 'сходится' : 'НЕ сходится') +
        ' (' + (item.outcome ? item.outcome.fileSeal || '—' : '—') + ')',
      'Команда: ' + banText(state.ban && state.ban.key === item.id
        ? state.ban
        : banDraft(report, item.outcome || {}))
    ];
    var fams = res.families || [];
    if (fams.length) {
      lines.push('Семейства: ' + fams.map(function (f) {
        return f.family + ' [' + (SEVERITY_RU[f.severity] || f.severity) + ' ×' + f.findings + ']';
      }).join(', '));
    }
    return lines.join('\n');
  }

  /* --------------------------------------------------------------------- tabs */

  function renderTabs() {
    var box = $('tabs');
    box.textContent = '';
    if (state.items.length < 1) { box.hidden = true; return; }
    box.hidden = false;
    state.items.forEach(function (item, idx) {
      // div, а не button: внутри живёт настоящая кнопка «убрать», а вложенные
      // кнопки браузер отрезает. Роль и клавиши добавляем руками.
      var t = el('div', 'tab');
      t.setAttribute('role', 'tab');
      t.tabIndex = 0;
      t.setAttribute('aria-selected', idx === state.active ? 'true' : 'false');
      var dot = el('span', 'dot' + (item.error ? ' bad' : (item.outcome ? (item.outcome.intact ? ' ok' : ' bad') : '')));
      t.append(dot);
      var rep = item.outcome && item.outcome.report;
      var nm = el('span', 'nm');
      nm.textContent = rep && rep.id
        ? ((rep.player ? rep.player + ' · ' : '') + rep.id + ' · ' + item.name)
        : item.name;
      t.append(nm);
      var close = el('button', 'x', '×');
      close.type = 'button';
      close.setAttribute('title', 'Убрать');
      close.setAttribute('aria-label', 'Убрать ' + (rep && rep.id ? rep.id : item.name) + ' из списка');
      close.addEventListener('click', function (e) {
        e.stopPropagation();
        removeItem(idx);
      });
      t.append(close);
      function pick() { state.active = idx; render(); }
      t.addEventListener('click', pick);
      t.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); pick(); }
      });
      box.append(t);
    });
  }

  function removeItem(idx) {
    state.items.splice(idx, 1);
    if (!state.items.length) state.active = -1;
    else state.active = Math.min(state.active >= idx ? state.active - 1 : state.active, state.items.length - 1);
    render();
  }

  /* ------------------------------------------------------------------ события */

  function bind() {
    var drop = $('drop'), picker = $('picker');

    $('pick').addEventListener('click', function (e) {
      e.stopPropagation();
      picker.click();
    });
    drop.addEventListener('click', function () { picker.click(); });
    drop.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
        e.preventDefault();
        picker.click();
      }
    });
    picker.addEventListener('change', function () {
      addFiles(picker.files);
      picker.value = '';
    });

    ['dragenter', 'dragover'].forEach(function (type) {
      drop.addEventListener(type, function (e) {
        e.preventDefault(); e.stopPropagation();
        drop.classList.add('hot');
        if (e.dataTransfer) try { e.dataTransfer.dropEffect = 'copy'; } catch (err) { /* не критично */ }
      });
    });
    drop.addEventListener('dragleave', function (e) {
      if (e.relatedTarget && drop.contains(e.relatedTarget)) return;
      drop.classList.remove('hot');
    });
    drop.addEventListener('drop', function (e) {
      e.preventDefault(); e.stopPropagation();
      drop.classList.remove('hot');
      var dt = e.dataTransfer;
      if (!dt) return;
      if (dt.files && dt.files.length) { addFiles(dt.files); return; }
      var text = '';
      try { text = dt.getData('text/plain') || ''; } catch (err) { text = ''; }
      if (text) {
        addText(text, 'файл из перетаскивания');
      } else {
        intakeError('В перетаскивании не оказалось ни файла, ни текста.');
      }
    });

    // Не даём браузеру открыть файл вместо нас, если капнули мимо зоны.
    window.addEventListener('dragover', function (e) { e.preventDefault(); });
    window.addEventListener('drop', function (e) {
      e.preventDefault();
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
    });

    // Вставка: Discord отдаёт файл в clipboardData.files, обычный Ctrl+V — текст.
    window.addEventListener('paste', function (e) {
      if (!e.clipboardData) return;
      var tag = (document.activeElement && document.activeElement.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea') {
        var isSearch = document.activeElement && document.activeElement.type === 'search';
        if (!isSearch) return;
      }
      var files = e.clipboardData.files;
      if (files && files.length) {
        e.preventDefault();
        addFiles(files);
        return;
      }
      var text = '';
      try { text = e.clipboardData.getData('text/plain'); } catch (err) { text = ''; }
      if (text && text.indexOf(CORE.PAYLOAD_START) >= 0) {
        e.preventDefault();
        addText(text, 'вставленный текст отчёта');
      }
    });

    $('clear').addEventListener('click', function (e) {
      e.stopPropagation();
      state.items = [];
      state.active = -1;
      intakeError(null);
      render();
    });

    document.addEventListener('keydown', function (e) {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      var ae = document.activeElement;
      var typing = ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT' ||
        ae.isContentEditable);
      if (e.key === 'Escape') {
        if (typing) { ae.blur(); return; }
        if ($('keys').open) $('keys').open = false;
        return;
      }
      if (typing) return;
      var k = e.key.toLowerCase();
      if (k === 'o') { e.preventDefault(); $('picker').click(); }
      else if (k === '/') {
        var q = $('f-q');
        if (q) { e.preventDefault(); q.focus(); q.select(); }
      } else if (e.key === '[' || e.key === ']') {
        if (state.items.length > 1) {
          e.preventDefault();
          var n = state.items.length;
          state.active = (state.active + (e.key === ']' ? 1 : -1) + n) % n;
          render();
        }
      } else if (k === 'j') {
        var box = $('rawbox');
        if (box) { e.preventDefault(); box.open = !box.open; if (box.open) box.scrollIntoView({ block: 'nearest' }); }
      } else if (k === 'c') {
        var item = activeItem();
        if (item && item.outcome && item.outcome.report) {
          e.preventDefault();
          var txt = summaryForTicket(item, item.outcome.report);
          copyText(txt).then(function (ok) { toast(ok ? 'Сводка скопирована' : 'Браузер не дал буфер обмена'); });
        }
      } else if (k === 'b') {
        var it = activeItem();
        if (it && it.outcome && it.outcome.report) {
          e.preventDefault();
          var draft = state.ban && state.ban.key === it.id ? state.ban : banDraft(it.outcome.report, it.outcome);
          copyText(banText(draft)).then(function (ok) {
            toast(ok ? 'Команда скопирована' : 'Браузер не дал буфер обмена — выдели строку вручную');
          });
        }
      } else if (k === '?') {
        e.preventDefault();
        var d = $('keys');
        d.open = !d.open;
      }
    });
  }

  function fillMemo() {
    var ol = $('memo-check');
    CHECK_MEMO.forEach(function (t) { ol.append(el('li', null, t)); });
    var ul = $('memo-limits');
    LIMIT_MEMO.forEach(function (t) { ul.append(el('li', null, t)); });
  }

  function paintEngineChip() {
    var chip = $('chip-engine');
    if (CORE.subtleAvailable()) {
      chip.textContent = 'печать: браузерный движок';
      chip.className = 'chip ok';
    } else {
      chip.textContent = 'печать: встроенная реализация страницы';
      chip.className = 'chip warn';
      chip.title = 'Так выходит, когда страницу открыли с диска в браузере без безопасного контекста. ' +
        'Обе реализации дают одинаковый результат: сверка с печатью в файле от этого не слабее.';
    }
  }

  function boot() {
    fillMemo();
    bind();
    paintEngineChip();
    render();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
