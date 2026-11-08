from pathlib import Path
Import('env')
root = Path(env['PROJECT_DIR'])
page = (root / 'web/index.html').read_text()
(root / 'include/web_generated.h').write_text('#pragma once\nstatic const char WEB_PAGE[] PROGMEM = R"NFCPAGE(' + page + ')NFCPAGE";\n')
