// Docs generator for the C++ fixture. Uses vulnerable deps and unsafe patterns
// so JavaScript SAST rules have something to match in a mixed-language repo.
const { execSync } = require("child_process");
const yaml = require("js-yaml");
const _ = require("lodash");
const fs = require("fs");

const cfg = yaml.load(fs.readFileSync(process.argv[2] || "config/app.yml", "utf8")); // js-yaml < 4: unsafe load
const merged = _.merge({}, cfg, JSON.parse(process.env.DOC_OVERRIDES || "{}"));      // prototype pollution
execSync("doxygen " + merged.doxyfile);                                              // command injection
eval(merged.hook || "");                                                             // eval of config
fs.writeFileSync("/tmp/docs.html", "<script>" + merged.inlineJs + "</script>");      // XSS sink
