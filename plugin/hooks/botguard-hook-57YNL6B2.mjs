// BotGuard Claude Code hook (generated bundle, do not edit). Source: packages/cli/src/hook.ts
// Blocks installs of known-malicious, typosquatted or impersonating npm/PyPI packages.
import { createRequire as __bgCreateRequire } from "node:module"; const require = __bgCreateRequire(import.meta.url);
import {
  GUARDED_TOOLS,
  MAYBE_INSTALL,
  __commonJS,
  __toESM
} from "./botguard-chunk-H66DWGCU.mjs";

// node_modules/semver/internal/constants.js
var require_constants = __commonJS({
  "node_modules/semver/internal/constants.js"(exports, module) {
    "use strict";
    var SEMVER_SPEC_VERSION = "2.0.0";
    var MAX_LENGTH = 256;
    var MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER || /* istanbul ignore next */
    9007199254740991;
    var MAX_SAFE_COMPONENT_LENGTH = 16;
    var MAX_SAFE_BUILD_LENGTH = MAX_LENGTH - 6;
    var RELEASE_TYPES = [
      "major",
      "premajor",
      "minor",
      "preminor",
      "patch",
      "prepatch",
      "prerelease"
    ];
    module.exports = {
      MAX_LENGTH,
      MAX_SAFE_COMPONENT_LENGTH,
      MAX_SAFE_BUILD_LENGTH,
      MAX_SAFE_INTEGER,
      RELEASE_TYPES,
      SEMVER_SPEC_VERSION,
      FLAG_INCLUDE_PRERELEASE: 1,
      FLAG_LOOSE: 2
    };
  }
});

// node_modules/semver/internal/debug.js
var require_debug = __commonJS({
  "node_modules/semver/internal/debug.js"(exports, module) {
    "use strict";
    var debug = typeof process === "object" && process.env && process.env.NODE_DEBUG && /\bsemver\b/i.test(process.env.NODE_DEBUG) ? (...args) => console.error("SEMVER", ...args) : () => {
    };
    module.exports = debug;
  }
});

// node_modules/semver/internal/re.js
var require_re = __commonJS({
  "node_modules/semver/internal/re.js"(exports, module) {
    "use strict";
    var {
      MAX_SAFE_COMPONENT_LENGTH,
      MAX_SAFE_BUILD_LENGTH,
      MAX_LENGTH
    } = require_constants();
    var debug = require_debug();
    exports = module.exports = {};
    var re = exports.re = [];
    var safeRe = exports.safeRe = [];
    var src = exports.src = [];
    var safeSrc = exports.safeSrc = [];
    var t = exports.t = {};
    var R = 0;
    var LETTERDASHNUMBER = "[a-zA-Z0-9-]";
    var safeRegexReplacements = [
      ["\\s", 1],
      ["\\d", MAX_LENGTH],
      [LETTERDASHNUMBER, MAX_SAFE_BUILD_LENGTH]
    ];
    var makeSafeRegex = (value) => {
      for (const [token, max] of safeRegexReplacements) {
        value = value.split(`${token}*`).join(`${token}{0,${max}}`).split(`${token}+`).join(`${token}{1,${max}}`);
      }
      return value;
    };
    var createToken = (name, value, isGlobal) => {
      const safe = makeSafeRegex(value);
      const index = R++;
      debug(name, index, value);
      t[name] = index;
      src[index] = value;
      safeSrc[index] = safe;
      re[index] = new RegExp(value, isGlobal ? "g" : void 0);
      safeRe[index] = new RegExp(safe, isGlobal ? "g" : void 0);
    };
    createToken("NUMERICIDENTIFIER", "0|[1-9]\\d*");
    createToken("NUMERICIDENTIFIERLOOSE", "\\d+");
    createToken("NONNUMERICIDENTIFIER", `\\d*[a-zA-Z-]${LETTERDASHNUMBER}*`);
    createToken("MAINVERSION", `(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})`);
    createToken("MAINVERSIONLOOSE", `(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})`);
    createToken("PRERELEASEIDENTIFIER", `(?:${src[t.NONNUMERICIDENTIFIER]}|${src[t.NUMERICIDENTIFIER]})`);
    createToken("PRERELEASEIDENTIFIERLOOSE", `(?:${src[t.NONNUMERICIDENTIFIER]}|${src[t.NUMERICIDENTIFIERLOOSE]})`);
    createToken("PRERELEASE", `(?:-(${src[t.PRERELEASEIDENTIFIER]}(?:\\.${src[t.PRERELEASEIDENTIFIER]})*))`);
    createToken("PRERELEASELOOSE", `(?:-?(${src[t.PRERELEASEIDENTIFIERLOOSE]}(?:\\.${src[t.PRERELEASEIDENTIFIERLOOSE]})*))`);
    createToken("BUILDIDENTIFIER", `${LETTERDASHNUMBER}+`);
    createToken("BUILD", `(?:\\+(${src[t.BUILDIDENTIFIER]}(?:\\.${src[t.BUILDIDENTIFIER]})*))`);
    createToken("FULLPLAIN", `v?${src[t.MAINVERSION]}${src[t.PRERELEASE]}?${src[t.BUILD]}?`);
    createToken("FULL", `^${src[t.FULLPLAIN]}$`);
    createToken("LOOSEPLAIN", `[v=\\s]*${src[t.MAINVERSIONLOOSE]}${src[t.PRERELEASELOOSE]}?${src[t.BUILD]}?`);
    createToken("LOOSE", `^${src[t.LOOSEPLAIN]}$`);
    createToken("GTLT", "((?:<|>)?=?)");
    createToken("XRANGEIDENTIFIERLOOSE", `${src[t.NUMERICIDENTIFIERLOOSE]}|x|X|\\*`);
    createToken("XRANGEIDENTIFIER", `${src[t.NUMERICIDENTIFIER]}|x|X|\\*`);
    createToken("XRANGEPLAIN", `[v=\\s]*(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:${src[t.PRERELEASE]})?${src[t.BUILD]}?)?)?`);
    createToken("XRANGEPLAINLOOSE", `[v=\\s]*(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:${src[t.PRERELEASELOOSE]})?${src[t.BUILD]}?)?)?`);
    createToken("XRANGE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAIN]}$`);
    createToken("XRANGELOOSE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("COERCEPLAIN", `${"(^|[^\\d])(\\d{1,"}${MAX_SAFE_COMPONENT_LENGTH}})(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?`);
    createToken("COERCE", `${src[t.COERCEPLAIN]}(?:$|[^\\d])`);
    createToken("COERCEFULL", src[t.COERCEPLAIN] + `(?:${src[t.PRERELEASE]})?(?:${src[t.BUILD]})?(?:$|[^\\d])`);
    createToken("COERCERTL", src[t.COERCE], true);
    createToken("COERCERTLFULL", src[t.COERCEFULL], true);
    createToken("LONETILDE", "(?:~>?)");
    createToken("TILDETRIM", `(\\s*)${src[t.LONETILDE]}\\s+`, true);
    exports.tildeTrimReplace = "$1~";
    createToken("TILDE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAIN]}$`);
    createToken("TILDELOOSE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("LONECARET", "(?:\\^)");
    createToken("CARETTRIM", `(\\s*)${src[t.LONECARET]}\\s+`, true);
    exports.caretTrimReplace = "$1^";
    createToken("CARET", `^${src[t.LONECARET]}${src[t.XRANGEPLAIN]}$`);
    createToken("CARETLOOSE", `^${src[t.LONECARET]}${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("COMPARATORLOOSE", `^${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]})$|^$`);
    createToken("COMPARATOR", `^${src[t.GTLT]}\\s*(${src[t.FULLPLAIN]})$|^$`);
    createToken("COMPARATORTRIM", `(\\s*)${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]}|${src[t.XRANGEPLAIN]})`, true);
    exports.comparatorTrimReplace = "$1$2$3";
    createToken("HYPHENRANGE", `^\\s*(${src[t.XRANGEPLAIN]})\\s+-\\s+(${src[t.XRANGEPLAIN]})\\s*$`);
    createToken("HYPHENRANGELOOSE", `^\\s*(${src[t.XRANGEPLAINLOOSE]})\\s+-\\s+(${src[t.XRANGEPLAINLOOSE]})\\s*$`);
    createToken("STAR", "(<|>)?=?\\s*\\*");
    createToken("GTE0", "^\\s*>=\\s*0\\.0\\.0\\s*$");
    createToken("GTE0PRE", "^\\s*>=\\s*0\\.0\\.0-0\\s*$");
  }
});

// node_modules/semver/internal/parse-options.js
var require_parse_options = __commonJS({
  "node_modules/semver/internal/parse-options.js"(exports, module) {
    "use strict";
    var looseOption = Object.freeze({ loose: true });
    var emptyOpts = Object.freeze({});
    var parseOptions = (options) => {
      if (!options) {
        return emptyOpts;
      }
      if (typeof options !== "object") {
        return looseOption;
      }
      return options;
    };
    module.exports = parseOptions;
  }
});

// node_modules/semver/internal/identifiers.js
var require_identifiers = __commonJS({
  "node_modules/semver/internal/identifiers.js"(exports, module) {
    "use strict";
    var numeric = /^[0-9]+$/;
    var compareIdentifiers = (a, b) => {
      if (typeof a === "number" && typeof b === "number") {
        return a === b ? 0 : a < b ? -1 : 1;
      }
      const anum = numeric.test(a);
      const bnum = numeric.test(b);
      if (anum && bnum) {
        a = +a;
        b = +b;
      }
      return a === b ? 0 : anum && !bnum ? -1 : bnum && !anum ? 1 : a < b ? -1 : 1;
    };
    var rcompareIdentifiers = (a, b) => compareIdentifiers(b, a);
    module.exports = {
      compareIdentifiers,
      rcompareIdentifiers
    };
  }
});

// node_modules/semver/classes/semver.js
var require_semver = __commonJS({
  "node_modules/semver/classes/semver.js"(exports, module) {
    "use strict";
    var debug = require_debug();
    var { MAX_LENGTH, MAX_SAFE_INTEGER } = require_constants();
    var { safeRe: re, t } = require_re();
    var parseOptions = require_parse_options();
    var { compareIdentifiers } = require_identifiers();
    var isPrereleaseIdentifier = (prerelease, identifier) => {
      const identifiers = identifier.split(".");
      if (identifiers.length > prerelease.length) {
        return false;
      }
      for (let i = 0; i < identifiers.length; i++) {
        if (compareIdentifiers(prerelease[i], identifiers[i]) !== 0) {
          return false;
        }
      }
      return true;
    };
    var SemVer = class _SemVer {
      constructor(version, options) {
        options = parseOptions(options);
        if (version instanceof _SemVer) {
          if (version.loose === !!options.loose && version.includePrerelease === !!options.includePrerelease) {
            return version;
          } else {
            version = version.version;
          }
        } else if (typeof version !== "string") {
          throw new TypeError(`Invalid version. Must be a string. Got type "${typeof version}".`);
        }
        if (version.length > MAX_LENGTH) {
          throw new TypeError(
            `version is longer than ${MAX_LENGTH} characters`
          );
        }
        debug("SemVer", version, options);
        this.options = options;
        this.loose = !!options.loose;
        this.includePrerelease = !!options.includePrerelease;
        const m = version.trim().match(options.loose ? re[t.LOOSE] : re[t.FULL]);
        if (!m) {
          throw new TypeError(`Invalid Version: ${version}`);
        }
        this.raw = version;
        this.major = +m[1];
        this.minor = +m[2];
        this.patch = +m[3];
        if (this.major > MAX_SAFE_INTEGER || this.major < 0) {
          throw new TypeError("Invalid major version");
        }
        if (this.minor > MAX_SAFE_INTEGER || this.minor < 0) {
          throw new TypeError("Invalid minor version");
        }
        if (this.patch > MAX_SAFE_INTEGER || this.patch < 0) {
          throw new TypeError("Invalid patch version");
        }
        if (!m[4]) {
          this.prerelease = [];
        } else {
          this.prerelease = m[4].split(".").map((id) => {
            if (/^[0-9]+$/.test(id)) {
              const num = +id;
              if (num >= 0 && num < MAX_SAFE_INTEGER) {
                return num;
              }
            }
            return id;
          });
        }
        this.build = m[5] ? m[5].split(".") : [];
        this.format();
      }
      format() {
        this.version = `${this.major}.${this.minor}.${this.patch}`;
        if (this.prerelease.length) {
          this.version += `-${this.prerelease.join(".")}`;
        }
        return this.version;
      }
      toString() {
        return this.version;
      }
      compare(other) {
        debug("SemVer.compare", this.version, this.options, other);
        if (!(other instanceof _SemVer)) {
          if (typeof other === "string" && other === this.version) {
            return 0;
          }
          other = new _SemVer(other, this.options);
        }
        if (other.version === this.version) {
          return 0;
        }
        return this.compareMain(other) || this.comparePre(other);
      }
      compareMain(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        if (this.major < other.major) {
          return -1;
        }
        if (this.major > other.major) {
          return 1;
        }
        if (this.minor < other.minor) {
          return -1;
        }
        if (this.minor > other.minor) {
          return 1;
        }
        if (this.patch < other.patch) {
          return -1;
        }
        if (this.patch > other.patch) {
          return 1;
        }
        return 0;
      }
      comparePre(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        if (this.prerelease.length && !other.prerelease.length) {
          return -1;
        } else if (!this.prerelease.length && other.prerelease.length) {
          return 1;
        } else if (!this.prerelease.length && !other.prerelease.length) {
          return 0;
        }
        let i = 0;
        do {
          const a = this.prerelease[i];
          const b = other.prerelease[i];
          debug("prerelease compare", i, a, b);
          if (a === void 0 && b === void 0) {
            return 0;
          } else if (b === void 0) {
            return 1;
          } else if (a === void 0) {
            return -1;
          } else if (a === b) {
            continue;
          } else {
            return compareIdentifiers(a, b);
          }
        } while (++i);
      }
      compareBuild(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        let i = 0;
        do {
          const a = this.build[i];
          const b = other.build[i];
          debug("build compare", i, a, b);
          if (a === void 0 && b === void 0) {
            return 0;
          } else if (b === void 0) {
            return 1;
          } else if (a === void 0) {
            return -1;
          } else if (a === b) {
            continue;
          } else {
            return compareIdentifiers(a, b);
          }
        } while (++i);
      }
      // preminor will bump the version up to the next minor release, and immediately
      // down to pre-release. premajor and prepatch work the same way.
      inc(release, identifier, identifierBase) {
        if (release.startsWith("pre")) {
          if (!identifier && identifierBase === false) {
            throw new Error("invalid increment argument: identifier is empty");
          }
          if (identifier) {
            const match = `-${identifier}`.match(this.options.loose ? re[t.PRERELEASELOOSE] : re[t.PRERELEASE]);
            if (!match || match[1] !== identifier) {
              throw new Error(`invalid identifier: ${identifier}`);
            }
          }
        }
        switch (release) {
          case "premajor":
            this.prerelease.length = 0;
            this.patch = 0;
            this.minor = 0;
            this.major++;
            this.inc("pre", identifier, identifierBase);
            break;
          case "preminor":
            this.prerelease.length = 0;
            this.patch = 0;
            this.minor++;
            this.inc("pre", identifier, identifierBase);
            break;
          case "prepatch":
            this.prerelease.length = 0;
            this.inc("patch", identifier, identifierBase);
            this.inc("pre", identifier, identifierBase);
            break;
          // If the input is a non-prerelease version, this acts the same as
          // prepatch.
          case "prerelease":
            if (this.prerelease.length === 0) {
              this.inc("patch", identifier, identifierBase);
            }
            this.inc("pre", identifier, identifierBase);
            break;
          case "release":
            if (this.prerelease.length === 0) {
              throw new Error(`version ${this.raw} is not a prerelease`);
            }
            this.prerelease.length = 0;
            break;
          case "major":
            if (this.minor !== 0 || this.patch !== 0 || this.prerelease.length === 0) {
              this.major++;
            }
            this.minor = 0;
            this.patch = 0;
            this.prerelease = [];
            break;
          case "minor":
            if (this.patch !== 0 || this.prerelease.length === 0) {
              this.minor++;
            }
            this.patch = 0;
            this.prerelease = [];
            break;
          case "patch":
            if (this.prerelease.length === 0) {
              this.patch++;
            }
            this.prerelease = [];
            break;
          // This probably shouldn't be used publicly.
          // 1.0.0 'pre' would become 1.0.0-0 which is the wrong direction.
          case "pre": {
            const base2 = Number(identifierBase) ? 1 : 0;
            if (this.prerelease.length === 0) {
              this.prerelease = [base2];
            } else {
              let i = this.prerelease.length;
              while (--i >= 0) {
                if (typeof this.prerelease[i] === "number") {
                  this.prerelease[i]++;
                  i = -2;
                }
              }
              if (i === -1) {
                if (identifier === this.prerelease.join(".") && identifierBase === false) {
                  throw new Error("invalid increment argument: identifier already exists");
                }
                this.prerelease.push(base2);
              }
            }
            if (identifier) {
              let prerelease = [identifier, base2];
              if (identifierBase === false) {
                prerelease = [identifier];
              }
              if (isPrereleaseIdentifier(this.prerelease, identifier)) {
                const prereleaseBase = this.prerelease[identifier.split(".").length];
                if (isNaN(prereleaseBase)) {
                  this.prerelease = prerelease;
                }
              } else {
                this.prerelease = prerelease;
              }
            }
            break;
          }
          default:
            throw new Error(`invalid increment argument: ${release}`);
        }
        this.raw = this.format();
        if (this.build.length) {
          this.raw += `+${this.build.join(".")}`;
        }
        return this;
      }
    };
    module.exports = SemVer;
  }
});

// node_modules/semver/functions/parse.js
var require_parse = __commonJS({
  "node_modules/semver/functions/parse.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var parse = (version, options, throwErrors = false) => {
      if (version instanceof SemVer) {
        return version;
      }
      try {
        return new SemVer(version, options);
      } catch (er) {
        if (!throwErrors) {
          return null;
        }
        throw er;
      }
    };
    module.exports = parse;
  }
});

// node_modules/semver/functions/valid.js
var require_valid = __commonJS({
  "node_modules/semver/functions/valid.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var valid = (version, options) => {
      const v = parse(version, options);
      return v ? v.version : null;
    };
    module.exports = valid;
  }
});

// node_modules/semver/functions/clean.js
var require_clean = __commonJS({
  "node_modules/semver/functions/clean.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var clean = (version, options) => {
      const s = parse(version.trim().replace(/^[=v]+/, ""), options);
      return s ? s.version : null;
    };
    module.exports = clean;
  }
});

// node_modules/semver/functions/inc.js
var require_inc = __commonJS({
  "node_modules/semver/functions/inc.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var inc = (version, release, options, identifier, identifierBase) => {
      if (typeof options === "string") {
        identifierBase = identifier;
        identifier = options;
        options = void 0;
      }
      try {
        return new SemVer(
          version instanceof SemVer ? version.version : version,
          options
        ).inc(release, identifier, identifierBase).version;
      } catch (er) {
        return null;
      }
    };
    module.exports = inc;
  }
});

// node_modules/semver/functions/diff.js
var require_diff = __commonJS({
  "node_modules/semver/functions/diff.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var diff = (version1, version2) => {
      const v1 = parse(version1, null, true);
      const v2 = parse(version2, null, true);
      const comparison = v1.compare(v2);
      if (comparison === 0) {
        return null;
      }
      const v1Higher = comparison > 0;
      const highVersion = v1Higher ? v1 : v2;
      const lowVersion = v1Higher ? v2 : v1;
      const highHasPre = !!highVersion.prerelease.length;
      const lowHasPre = !!lowVersion.prerelease.length;
      if (lowHasPre && !highHasPre) {
        if (!lowVersion.patch && !lowVersion.minor) {
          return "major";
        }
        if (lowVersion.compareMain(highVersion) === 0) {
          if (lowVersion.minor && !lowVersion.patch) {
            return "minor";
          }
          return "patch";
        }
      }
      const prefix = highHasPre ? "pre" : "";
      if (v1.major !== v2.major) {
        return prefix + "major";
      }
      if (v1.minor !== v2.minor) {
        return prefix + "minor";
      }
      if (v1.patch !== v2.patch) {
        return prefix + "patch";
      }
      return "prerelease";
    };
    module.exports = diff;
  }
});

// node_modules/semver/functions/major.js
var require_major = __commonJS({
  "node_modules/semver/functions/major.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var major = (a, loose) => new SemVer(a, loose).major;
    module.exports = major;
  }
});

// node_modules/semver/functions/minor.js
var require_minor = __commonJS({
  "node_modules/semver/functions/minor.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var minor = (a, loose) => new SemVer(a, loose).minor;
    module.exports = minor;
  }
});

// node_modules/semver/functions/patch.js
var require_patch = __commonJS({
  "node_modules/semver/functions/patch.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var patch = (a, loose) => new SemVer(a, loose).patch;
    module.exports = patch;
  }
});

// node_modules/semver/functions/prerelease.js
var require_prerelease = __commonJS({
  "node_modules/semver/functions/prerelease.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var prerelease = (version, options) => {
      const parsed = parse(version, options);
      return parsed && parsed.prerelease.length ? parsed.prerelease : null;
    };
    module.exports = prerelease;
  }
});

// node_modules/semver/functions/compare.js
var require_compare = __commonJS({
  "node_modules/semver/functions/compare.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var compare = (a, b, loose) => new SemVer(a, loose).compare(new SemVer(b, loose));
    module.exports = compare;
  }
});

// node_modules/semver/functions/rcompare.js
var require_rcompare = __commonJS({
  "node_modules/semver/functions/rcompare.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var rcompare = (a, b, loose) => compare(b, a, loose);
    module.exports = rcompare;
  }
});

// node_modules/semver/functions/compare-loose.js
var require_compare_loose = __commonJS({
  "node_modules/semver/functions/compare-loose.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var compareLoose = (a, b) => compare(a, b, true);
    module.exports = compareLoose;
  }
});

// node_modules/semver/functions/compare-build.js
var require_compare_build = __commonJS({
  "node_modules/semver/functions/compare-build.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var compareBuild = (a, b, loose) => {
      const versionA = new SemVer(a, loose);
      const versionB = new SemVer(b, loose);
      return versionA.compare(versionB) || versionA.compareBuild(versionB);
    };
    module.exports = compareBuild;
  }
});

// node_modules/semver/functions/sort.js
var require_sort = __commonJS({
  "node_modules/semver/functions/sort.js"(exports, module) {
    "use strict";
    var compareBuild = require_compare_build();
    var sort = (list, loose) => list.sort((a, b) => compareBuild(a, b, loose));
    module.exports = sort;
  }
});

// node_modules/semver/functions/rsort.js
var require_rsort = __commonJS({
  "node_modules/semver/functions/rsort.js"(exports, module) {
    "use strict";
    var compareBuild = require_compare_build();
    var rsort = (list, loose) => list.sort((a, b) => compareBuild(b, a, loose));
    module.exports = rsort;
  }
});

// node_modules/semver/functions/gt.js
var require_gt = __commonJS({
  "node_modules/semver/functions/gt.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var gt = (a, b, loose) => compare(a, b, loose) > 0;
    module.exports = gt;
  }
});

// node_modules/semver/functions/lt.js
var require_lt = __commonJS({
  "node_modules/semver/functions/lt.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var lt = (a, b, loose) => compare(a, b, loose) < 0;
    module.exports = lt;
  }
});

// node_modules/semver/functions/eq.js
var require_eq = __commonJS({
  "node_modules/semver/functions/eq.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var eq = (a, b, loose) => compare(a, b, loose) === 0;
    module.exports = eq;
  }
});

// node_modules/semver/functions/neq.js
var require_neq = __commonJS({
  "node_modules/semver/functions/neq.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var neq = (a, b, loose) => compare(a, b, loose) !== 0;
    module.exports = neq;
  }
});

// node_modules/semver/functions/gte.js
var require_gte = __commonJS({
  "node_modules/semver/functions/gte.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var gte = (a, b, loose) => compare(a, b, loose) >= 0;
    module.exports = gte;
  }
});

// node_modules/semver/functions/lte.js
var require_lte = __commonJS({
  "node_modules/semver/functions/lte.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var lte = (a, b, loose) => compare(a, b, loose) <= 0;
    module.exports = lte;
  }
});

// node_modules/semver/functions/cmp.js
var require_cmp = __commonJS({
  "node_modules/semver/functions/cmp.js"(exports, module) {
    "use strict";
    var eq = require_eq();
    var neq = require_neq();
    var gt = require_gt();
    var gte = require_gte();
    var lt = require_lt();
    var lte = require_lte();
    var cmp = (a, op, b, loose) => {
      switch (op) {
        case "===":
          if (typeof a === "object") {
            a = a.version;
          }
          if (typeof b === "object") {
            b = b.version;
          }
          return a === b;
        case "!==":
          if (typeof a === "object") {
            a = a.version;
          }
          if (typeof b === "object") {
            b = b.version;
          }
          return a !== b;
        case "":
        case "=":
        case "==":
          return eq(a, b, loose);
        case "!=":
          return neq(a, b, loose);
        case ">":
          return gt(a, b, loose);
        case ">=":
          return gte(a, b, loose);
        case "<":
          return lt(a, b, loose);
        case "<=":
          return lte(a, b, loose);
        default:
          throw new TypeError(`Invalid operator: ${op}`);
      }
    };
    module.exports = cmp;
  }
});

// node_modules/semver/functions/coerce.js
var require_coerce = __commonJS({
  "node_modules/semver/functions/coerce.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var parse = require_parse();
    var { safeRe: re, t } = require_re();
    var coerce = (version, options) => {
      if (version instanceof SemVer) {
        return version;
      }
      if (typeof version === "number") {
        version = String(version);
      }
      if (typeof version !== "string") {
        return null;
      }
      options = options || {};
      let match = null;
      if (!options.rtl) {
        match = version.match(options.includePrerelease ? re[t.COERCEFULL] : re[t.COERCE]);
      } else {
        const coerceRtlRegex = options.includePrerelease ? re[t.COERCERTLFULL] : re[t.COERCERTL];
        let next;
        while ((next = coerceRtlRegex.exec(version)) && (!match || match.index + match[0].length !== version.length)) {
          if (!match || next.index + next[0].length !== match.index + match[0].length) {
            match = next;
          }
          coerceRtlRegex.lastIndex = next.index + next[1].length + next[2].length;
        }
        coerceRtlRegex.lastIndex = -1;
      }
      if (match === null) {
        return null;
      }
      const major = match[2];
      const minor = match[3] || "0";
      const patch = match[4] || "0";
      const prerelease = options.includePrerelease && match[5] ? `-${match[5]}` : "";
      const build = options.includePrerelease && match[6] ? `+${match[6]}` : "";
      return parse(`${major}.${minor}.${patch}${prerelease}${build}`, options);
    };
    module.exports = coerce;
  }
});

// node_modules/semver/functions/truncate.js
var require_truncate = __commonJS({
  "node_modules/semver/functions/truncate.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var constants = require_constants();
    var SemVer = require_semver();
    var truncate = (version, truncation, options) => {
      if (!constants.RELEASE_TYPES.includes(truncation)) {
        return null;
      }
      const clonedVersion = cloneInputVersion(version, options);
      return clonedVersion && doTruncation(clonedVersion, truncation);
    };
    var cloneInputVersion = (version, options) => {
      const versionStringToParse = version instanceof SemVer ? version.version : version;
      return parse(versionStringToParse, options);
    };
    var doTruncation = (version, truncation) => {
      if (isPrerelease2(truncation)) {
        return version.version;
      }
      version.prerelease = [];
      switch (truncation) {
        case "major":
          version.minor = 0;
          version.patch = 0;
          break;
        case "minor":
          version.patch = 0;
          break;
      }
      return version.format();
    };
    var isPrerelease2 = (type) => {
      return type.startsWith("pre");
    };
    module.exports = truncate;
  }
});

// node_modules/semver/internal/lrucache.js
var require_lrucache = __commonJS({
  "node_modules/semver/internal/lrucache.js"(exports, module) {
    "use strict";
    var LRUCache = class {
      constructor() {
        this.max = 1e3;
        this.map = /* @__PURE__ */ new Map();
      }
      get(key2) {
        const value = this.map.get(key2);
        if (value === void 0) {
          return void 0;
        } else {
          this.map.delete(key2);
          this.map.set(key2, value);
          return value;
        }
      }
      delete(key2) {
        return this.map.delete(key2);
      }
      set(key2, value) {
        const deleted = this.delete(key2);
        if (!deleted && value !== void 0) {
          if (this.map.size >= this.max) {
            const firstKey = this.map.keys().next().value;
            this.delete(firstKey);
          }
          this.map.set(key2, value);
        }
        return this;
      }
    };
    module.exports = LRUCache;
  }
});

// node_modules/semver/classes/range.js
var require_range = __commonJS({
  "node_modules/semver/classes/range.js"(exports, module) {
    "use strict";
    var SPACE_CHARACTERS = /\s+/g;
    var Range = class _Range {
      constructor(range, options) {
        options = parseOptions(options);
        if (range instanceof _Range) {
          if (range.loose === !!options.loose && range.includePrerelease === !!options.includePrerelease) {
            return range;
          } else {
            return new _Range(range.raw, options);
          }
        }
        if (range instanceof Comparator) {
          this.raw = range.value;
          this.set = [[range]];
          this.formatted = void 0;
          return this;
        }
        this.options = options;
        this.loose = !!options.loose;
        this.includePrerelease = !!options.includePrerelease;
        this.raw = range.trim().replace(SPACE_CHARACTERS, " ");
        this.set = this.raw.split("||").map((r) => this.parseRange(r.trim())).filter((c) => c.length);
        if (!this.set.length) {
          throw new TypeError(`Invalid SemVer Range: ${this.raw}`);
        }
        if (this.set.length > 1) {
          const first = this.set[0];
          this.set = this.set.filter((c) => !isNullSet(c[0]));
          if (this.set.length === 0) {
            this.set = [first];
          } else if (this.set.length > 1) {
            for (const c of this.set) {
              if (c.length === 1 && isAny(c[0])) {
                this.set = [c];
                break;
              }
            }
          }
        }
        this.formatted = void 0;
      }
      get range() {
        if (this.formatted === void 0) {
          this.formatted = "";
          for (let i = 0; i < this.set.length; i++) {
            if (i > 0) {
              this.formatted += "||";
            }
            const comps = this.set[i];
            for (let k = 0; k < comps.length; k++) {
              if (k > 0) {
                this.formatted += " ";
              }
              this.formatted += comps[k].toString().trim();
            }
          }
        }
        return this.formatted;
      }
      format() {
        return this.range;
      }
      toString() {
        return this.range;
      }
      parseRange(range) {
        range = range.replace(BUILDSTRIPRE, "");
        const memoOpts = (this.options.includePrerelease && FLAG_INCLUDE_PRERELEASE) | (this.options.loose && FLAG_LOOSE);
        const memoKey = memoOpts + ":" + range;
        const cached = cache.get(memoKey);
        if (cached) {
          return cached;
        }
        const loose = this.options.loose;
        const hr = loose ? re[t.HYPHENRANGELOOSE] : re[t.HYPHENRANGE];
        range = range.replace(hr, hyphenReplace(this.options.includePrerelease));
        debug("hyphen replace", range);
        range = range.replace(re[t.COMPARATORTRIM], comparatorTrimReplace);
        debug("comparator trim", range);
        range = range.replace(re[t.TILDETRIM], tildeTrimReplace);
        debug("tilde trim", range);
        range = range.replace(re[t.CARETTRIM], caretTrimReplace);
        debug("caret trim", range);
        let rangeList = range.split(" ").map((comp) => parseComparator(comp, this.options)).join(" ").split(/\s+/).map((comp) => replaceGTE0(comp, this.options));
        if (loose) {
          rangeList = rangeList.filter((comp) => {
            debug("loose invalid filter", comp, this.options);
            return !!comp.match(re[t.COMPARATORLOOSE]);
          });
        }
        debug("range list", rangeList);
        const rangeMap = /* @__PURE__ */ new Map();
        const comparators = rangeList.map((comp) => new Comparator(comp, this.options));
        for (const comp of comparators) {
          if (isNullSet(comp)) {
            return [comp];
          }
          rangeMap.set(comp.value, comp);
        }
        if (rangeMap.size > 1 && rangeMap.has("")) {
          rangeMap.delete("");
        }
        const result = [...rangeMap.values()];
        cache.set(memoKey, result);
        return result;
      }
      intersects(range, options) {
        if (!(range instanceof _Range)) {
          throw new TypeError("a Range is required");
        }
        return this.set.some((thisComparators) => {
          return isSatisfiable(thisComparators, options) && range.set.some((rangeComparators) => {
            return isSatisfiable(rangeComparators, options) && thisComparators.every((thisComparator) => {
              return rangeComparators.every((rangeComparator) => {
                return thisComparator.intersects(rangeComparator, options);
              });
            });
          });
        });
      }
      // if ANY of the sets match ALL of its comparators, then pass
      test(version) {
        if (!version) {
          return false;
        }
        if (typeof version === "string") {
          try {
            version = new SemVer(version, this.options);
          } catch (er) {
            return false;
          }
        }
        for (let i = 0; i < this.set.length; i++) {
          if (testSet(this.set[i], version, this.options)) {
            return true;
          }
        }
        return false;
      }
    };
    module.exports = Range;
    var LRU = require_lrucache();
    var cache = new LRU();
    var parseOptions = require_parse_options();
    var Comparator = require_comparator();
    var debug = require_debug();
    var SemVer = require_semver();
    var {
      safeRe: re,
      src,
      t,
      comparatorTrimReplace,
      tildeTrimReplace,
      caretTrimReplace
    } = require_re();
    var { FLAG_INCLUDE_PRERELEASE, FLAG_LOOSE } = require_constants();
    var BUILDSTRIPRE = new RegExp(src[t.BUILD], "g");
    var isNullSet = (c) => c.value === "<0.0.0-0";
    var isAny = (c) => c.value === "";
    var isSatisfiable = (comparators, options) => {
      let result = true;
      const remainingComparators = comparators.slice();
      let testComparator = remainingComparators.pop();
      while (result && remainingComparators.length) {
        result = remainingComparators.every((otherComparator) => {
          return testComparator.intersects(otherComparator, options);
        });
        testComparator = remainingComparators.pop();
      }
      return result;
    };
    var parseComparator = (comp, options) => {
      comp = comp.replace(re[t.BUILD], "");
      debug("comp", comp, options);
      comp = replaceCarets(comp, options);
      debug("caret", comp);
      comp = replaceTildes(comp, options);
      debug("tildes", comp);
      comp = replaceXRanges(comp, options);
      debug("xrange", comp);
      comp = replaceStars(comp, options);
      debug("stars", comp);
      return comp;
    };
    var isX = (id) => !id || id.toLowerCase() === "x" || id === "*";
    var invalidXRangeOrder = (M, m, p) => isX(M) && !isX(m) || isX(m) && p && !isX(p);
    var replaceTildes = (comp, options) => {
      return comp.trim().split(/\s+/).map((c) => replaceTilde(c, options)).join(" ");
    };
    var replaceTilde = (comp, options) => {
      const r = options.loose ? re[t.TILDELOOSE] : re[t.TILDE];
      const z = options.includePrerelease ? "-0" : "";
      return comp.replace(r, (_, M, m, p, pr) => {
        debug("tilde", comp, _, M, m, p, pr);
        let ret;
        if (isX(M)) {
          ret = "";
        } else if (isX(m)) {
          ret = `>=${M}.0.0${z} <${+M + 1}.0.0-0`;
        } else if (isX(p)) {
          ret = `>=${M}.${m}.0${z} <${M}.${+m + 1}.0-0`;
        } else if (pr) {
          debug("replaceTilde pr", pr);
          ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
        } else {
          ret = `>=${M}.${m}.${p} <${M}.${+m + 1}.0-0`;
        }
        debug("tilde return", ret);
        return ret;
      });
    };
    var replaceCarets = (comp, options) => {
      return comp.trim().split(/\s+/).map((c) => replaceCaret(c, options)).join(" ");
    };
    var replaceCaret = (comp, options) => {
      debug("caret", comp, options);
      const r = options.loose ? re[t.CARETLOOSE] : re[t.CARET];
      const z = options.includePrerelease ? "-0" : "";
      return comp.replace(r, (_, M, m, p, pr) => {
        debug("caret", comp, _, M, m, p, pr);
        let ret;
        if (isX(M)) {
          ret = "";
        } else if (isX(m)) {
          ret = `>=${M}.0.0${z} <${+M + 1}.0.0-0`;
        } else if (isX(p)) {
          if (M === "0") {
            ret = `>=${M}.${m}.0${z} <${M}.${+m + 1}.0-0`;
          } else {
            ret = `>=${M}.${m}.0${z} <${+M + 1}.0.0-0`;
          }
        } else if (pr) {
          debug("replaceCaret pr", pr);
          if (M === "0") {
            if (m === "0") {
              ret = `>=${M}.${m}.${p}-${pr} <${M}.${m}.${+p + 1}-0`;
            } else {
              ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
            }
          } else {
            ret = `>=${M}.${m}.${p}-${pr} <${+M + 1}.0.0-0`;
          }
        } else {
          debug("no pr");
          if (M === "0") {
            if (m === "0") {
              ret = `>=${M}.${m}.${p} <${M}.${m}.${+p + 1}-0`;
            } else {
              ret = `>=${M}.${m}.${p} <${M}.${+m + 1}.0-0`;
            }
          } else {
            ret = `>=${M}.${m}.${p} <${+M + 1}.0.0-0`;
          }
        }
        debug("caret return", ret);
        return ret;
      });
    };
    var replaceXRanges = (comp, options) => {
      debug("replaceXRanges", comp, options);
      return comp.split(/\s+/).map((c) => replaceXRange(c, options)).join(" ");
    };
    var replaceXRange = (comp, options) => {
      comp = comp.trim();
      const r = options.loose ? re[t.XRANGELOOSE] : re[t.XRANGE];
      return comp.replace(r, (ret, gtlt, M, m, p, pr) => {
        debug("xRange", comp, ret, gtlt, M, m, p, pr);
        if (invalidXRangeOrder(M, m, p)) {
          return comp;
        }
        const xM = isX(M);
        const xm = xM || isX(m);
        const xp = xm || isX(p);
        const anyX = xp;
        if (gtlt === "=" && anyX) {
          gtlt = "";
        }
        pr = options.includePrerelease ? "-0" : "";
        if (xM) {
          if (gtlt === ">" || gtlt === "<") {
            ret = "<0.0.0-0";
          } else {
            ret = "*";
          }
        } else if (gtlt && anyX) {
          if (xm) {
            m = 0;
          }
          p = 0;
          if (gtlt === ">") {
            gtlt = ">=";
            if (xm) {
              M = +M + 1;
              m = 0;
              p = 0;
            } else {
              m = +m + 1;
              p = 0;
            }
          } else if (gtlt === "<=") {
            gtlt = "<";
            if (xm) {
              M = +M + 1;
            } else {
              m = +m + 1;
            }
          }
          if (gtlt === "<") {
            pr = "-0";
          }
          ret = `${gtlt + M}.${m}.${p}${pr}`;
        } else if (xm) {
          ret = `>=${M}.0.0${pr} <${+M + 1}.0.0-0`;
        } else if (xp) {
          ret = `>=${M}.${m}.0${pr} <${M}.${+m + 1}.0-0`;
        }
        debug("xRange return", ret);
        return ret;
      });
    };
    var replaceStars = (comp, options) => {
      debug("replaceStars", comp, options);
      return comp.trim().replace(re[t.STAR], "");
    };
    var replaceGTE0 = (comp, options) => {
      debug("replaceGTE0", comp, options);
      return comp.trim().replace(re[options.includePrerelease ? t.GTE0PRE : t.GTE0], "");
    };
    var hyphenReplace = (incPr) => ($0, from, fM, fm, fp, fpr, fb, to, tM, tm, tp, tpr) => {
      if (isX(fM)) {
        from = "";
      } else if (isX(fm)) {
        from = `>=${fM}.0.0${incPr ? "-0" : ""}`;
      } else if (isX(fp)) {
        from = `>=${fM}.${fm}.0${incPr ? "-0" : ""}`;
      } else if (fpr) {
        from = `>=${from}`;
      } else {
        from = `>=${from}${incPr ? "-0" : ""}`;
      }
      if (isX(tM)) {
        to = "";
      } else if (isX(tm)) {
        to = `<${+tM + 1}.0.0-0`;
      } else if (isX(tp)) {
        to = `<${tM}.${+tm + 1}.0-0`;
      } else if (tpr) {
        to = `<=${tM}.${tm}.${tp}-${tpr}`;
      } else if (incPr) {
        to = `<${tM}.${tm}.${+tp + 1}-0`;
      } else {
        to = `<=${to}`;
      }
      return `${from} ${to}`.trim();
    };
    var testSet = (set, version, options) => {
      for (let i = 0; i < set.length; i++) {
        if (!set[i].test(version)) {
          return false;
        }
      }
      if (version.prerelease.length && !options.includePrerelease) {
        for (let i = 0; i < set.length; i++) {
          debug(set[i].semver);
          if (set[i].semver === Comparator.ANY) {
            continue;
          }
          if (set[i].semver.prerelease.length > 0) {
            const allowed = set[i].semver;
            if (allowed.major === version.major && allowed.minor === version.minor && allowed.patch === version.patch) {
              return true;
            }
          }
        }
        return false;
      }
      return true;
    };
  }
});

// node_modules/semver/classes/comparator.js
var require_comparator = __commonJS({
  "node_modules/semver/classes/comparator.js"(exports, module) {
    "use strict";
    var ANY = Symbol("SemVer ANY");
    var Comparator = class _Comparator {
      static get ANY() {
        return ANY;
      }
      constructor(comp, options) {
        options = parseOptions(options);
        if (comp instanceof _Comparator) {
          if (comp.loose === !!options.loose) {
            return comp;
          } else {
            comp = comp.value;
          }
        }
        comp = comp.trim().split(/\s+/).join(" ");
        debug("comparator", comp, options);
        this.options = options;
        this.loose = !!options.loose;
        this.parse(comp);
        if (this.semver === ANY) {
          this.value = "";
        } else {
          this.value = this.operator + this.semver.version;
        }
        debug("comp", this);
      }
      parse(comp) {
        const r = this.options.loose ? re[t.COMPARATORLOOSE] : re[t.COMPARATOR];
        const m = comp.match(r);
        if (!m) {
          throw new TypeError(`Invalid comparator: ${comp}`);
        }
        this.operator = m[1] !== void 0 ? m[1] : "";
        if (this.operator === "=") {
          this.operator = "";
        }
        if (!m[2]) {
          this.semver = ANY;
        } else {
          this.semver = new SemVer(m[2], this.options.loose);
        }
      }
      toString() {
        return this.value;
      }
      test(version) {
        debug("Comparator.test", version, this.options.loose);
        if (this.semver === ANY || version === ANY) {
          return true;
        }
        if (typeof version === "string") {
          try {
            version = new SemVer(version, this.options);
          } catch (er) {
            return false;
          }
        }
        return cmp(version, this.operator, this.semver, this.options);
      }
      intersects(comp, options) {
        if (!(comp instanceof _Comparator)) {
          throw new TypeError("a Comparator is required");
        }
        if (this.operator === "") {
          if (this.value === "") {
            return true;
          }
          return new Range(comp.value, options).test(this.value);
        } else if (comp.operator === "") {
          if (comp.value === "") {
            return true;
          }
          return new Range(this.value, options).test(comp.semver);
        }
        options = parseOptions(options);
        if (options.includePrerelease && (this.value === "<0.0.0-0" || comp.value === "<0.0.0-0")) {
          return false;
        }
        if (!options.includePrerelease && (this.value.startsWith("<0.0.0") || comp.value.startsWith("<0.0.0"))) {
          return false;
        }
        if (this.operator.startsWith(">") && comp.operator.startsWith(">")) {
          return true;
        }
        if (this.operator.startsWith("<") && comp.operator.startsWith("<")) {
          return true;
        }
        if (this.semver.version === comp.semver.version && this.operator.includes("=") && comp.operator.includes("=")) {
          return true;
        }
        if (cmp(this.semver, "<", comp.semver, options) && this.operator.startsWith(">") && comp.operator.startsWith("<")) {
          return true;
        }
        if (cmp(this.semver, ">", comp.semver, options) && this.operator.startsWith("<") && comp.operator.startsWith(">")) {
          return true;
        }
        return false;
      }
    };
    module.exports = Comparator;
    var parseOptions = require_parse_options();
    var { safeRe: re, t } = require_re();
    var cmp = require_cmp();
    var debug = require_debug();
    var SemVer = require_semver();
    var Range = require_range();
  }
});

// node_modules/semver/functions/satisfies.js
var require_satisfies = __commonJS({
  "node_modules/semver/functions/satisfies.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var satisfies = (version, range, options) => {
      try {
        range = new Range(range, options);
      } catch (er) {
        return false;
      }
      return range.test(version);
    };
    module.exports = satisfies;
  }
});

// node_modules/semver/ranges/to-comparators.js
var require_to_comparators = __commonJS({
  "node_modules/semver/ranges/to-comparators.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var toComparators = (range, options) => new Range(range, options).set.map((comp) => comp.map((c) => c.value).join(" ").trim().split(" "));
    module.exports = toComparators;
  }
});

// node_modules/semver/ranges/max-satisfying.js
var require_max_satisfying = __commonJS({
  "node_modules/semver/ranges/max-satisfying.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var Range = require_range();
    var maxSatisfying = (versions, range, options) => {
      let max = null;
      let maxSV = null;
      let rangeObj = null;
      try {
        rangeObj = new Range(range, options);
      } catch (er) {
        return null;
      }
      versions.forEach((v) => {
        if (rangeObj.test(v)) {
          if (!max || maxSV.compare(v) === -1) {
            max = v;
            maxSV = new SemVer(max, options);
          }
        }
      });
      return max;
    };
    module.exports = maxSatisfying;
  }
});

// node_modules/semver/ranges/min-satisfying.js
var require_min_satisfying = __commonJS({
  "node_modules/semver/ranges/min-satisfying.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var Range = require_range();
    var minSatisfying = (versions, range, options) => {
      let min = null;
      let minSV = null;
      let rangeObj = null;
      try {
        rangeObj = new Range(range, options);
      } catch (er) {
        return null;
      }
      versions.forEach((v) => {
        if (rangeObj.test(v)) {
          if (!min || minSV.compare(v) === 1) {
            min = v;
            minSV = new SemVer(min, options);
          }
        }
      });
      return min;
    };
    module.exports = minSatisfying;
  }
});

// node_modules/semver/ranges/min-version.js
var require_min_version = __commonJS({
  "node_modules/semver/ranges/min-version.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var Range = require_range();
    var gt = require_gt();
    var minVersion = (range, loose) => {
      range = new Range(range, loose);
      let minver = new SemVer("0.0.0");
      if (range.test(minver)) {
        return minver;
      }
      minver = new SemVer("0.0.0-0");
      if (range.test(minver)) {
        return minver;
      }
      minver = null;
      for (let i = 0; i < range.set.length; ++i) {
        const comparators = range.set[i];
        let setMin = null;
        comparators.forEach((comparator) => {
          const compver = new SemVer(comparator.semver.version);
          switch (comparator.operator) {
            case ">":
              if (compver.prerelease.length === 0) {
                compver.patch++;
              } else {
                compver.prerelease.push(0);
              }
              compver.raw = compver.format();
            /* fallthrough */
            case "":
            case ">=":
              if (!setMin || gt(compver, setMin)) {
                setMin = compver;
              }
              break;
            case "<":
            case "<=":
              break;
            /* istanbul ignore next */
            default:
              throw new Error(`Unexpected operation: ${comparator.operator}`);
          }
        });
        if (setMin && (!minver || gt(minver, setMin))) {
          minver = setMin;
        }
      }
      if (minver && range.test(minver)) {
        return minver;
      }
      return null;
    };
    module.exports = minVersion;
  }
});

// node_modules/semver/ranges/valid.js
var require_valid2 = __commonJS({
  "node_modules/semver/ranges/valid.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var validRange = (range, options) => {
      try {
        return new Range(range, options).range || "*";
      } catch (er) {
        return null;
      }
    };
    module.exports = validRange;
  }
});

// node_modules/semver/ranges/outside.js
var require_outside = __commonJS({
  "node_modules/semver/ranges/outside.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var Comparator = require_comparator();
    var { ANY } = Comparator;
    var Range = require_range();
    var satisfies = require_satisfies();
    var gt = require_gt();
    var lt = require_lt();
    var lte = require_lte();
    var gte = require_gte();
    var outside = (version, range, hilo, options) => {
      version = new SemVer(version, options);
      range = new Range(range, options);
      let gtfn, ltefn, ltfn, comp, ecomp;
      switch (hilo) {
        case ">":
          gtfn = gt;
          ltefn = lte;
          ltfn = lt;
          comp = ">";
          ecomp = ">=";
          break;
        case "<":
          gtfn = lt;
          ltefn = gte;
          ltfn = gt;
          comp = "<";
          ecomp = "<=";
          break;
        default:
          throw new TypeError('Must provide a hilo val of "<" or ">"');
      }
      if (satisfies(version, range, options)) {
        return false;
      }
      for (let i = 0; i < range.set.length; ++i) {
        const comparators = range.set[i];
        let high = null;
        let low = null;
        comparators.forEach((comparator) => {
          if (comparator.semver === ANY) {
            comparator = new Comparator(">=0.0.0");
          }
          high = high || comparator;
          low = low || comparator;
          if (gtfn(comparator.semver, high.semver, options)) {
            high = comparator;
          } else if (ltfn(comparator.semver, low.semver, options)) {
            low = comparator;
          }
        });
        if (high.operator === comp || high.operator === ecomp) {
          return false;
        }
        if ((!low.operator || low.operator === comp) && ltefn(version, low.semver)) {
          return false;
        } else if (low.operator === ecomp && ltfn(version, low.semver)) {
          return false;
        }
      }
      return true;
    };
    module.exports = outside;
  }
});

// node_modules/semver/ranges/gtr.js
var require_gtr = __commonJS({
  "node_modules/semver/ranges/gtr.js"(exports, module) {
    "use strict";
    var outside = require_outside();
    var gtr = (version, range, options) => outside(version, range, ">", options);
    module.exports = gtr;
  }
});

// node_modules/semver/ranges/ltr.js
var require_ltr = __commonJS({
  "node_modules/semver/ranges/ltr.js"(exports, module) {
    "use strict";
    var outside = require_outside();
    var ltr = (version, range, options) => outside(version, range, "<", options);
    module.exports = ltr;
  }
});

// node_modules/semver/ranges/intersects.js
var require_intersects = __commonJS({
  "node_modules/semver/ranges/intersects.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var intersects = (r1, r2, options) => {
      r1 = new Range(r1, options);
      r2 = new Range(r2, options);
      return r1.intersects(r2, options);
    };
    module.exports = intersects;
  }
});

// node_modules/semver/ranges/simplify.js
var require_simplify = __commonJS({
  "node_modules/semver/ranges/simplify.js"(exports, module) {
    "use strict";
    var satisfies = require_satisfies();
    var compare = require_compare();
    module.exports = (versions, range, options) => {
      const set = [];
      let first = null;
      let prev = null;
      const v = versions.sort((a, b) => compare(a, b, options));
      for (const version of v) {
        const included = satisfies(version, range, options);
        if (included) {
          prev = version;
          if (!first) {
            first = version;
          }
        } else {
          if (prev) {
            set.push([first, prev]);
          }
          prev = null;
          first = null;
        }
      }
      if (first) {
        set.push([first, null]);
      }
      const ranges = [];
      for (const [min, max] of set) {
        if (min === max) {
          ranges.push(min);
        } else if (!max && min === v[0]) {
          ranges.push("*");
        } else if (!max) {
          ranges.push(`>=${min}`);
        } else if (min === v[0]) {
          ranges.push(`<=${max}`);
        } else {
          ranges.push(`${min} - ${max}`);
        }
      }
      const simplified = ranges.join(" || ");
      const original = typeof range.raw === "string" ? range.raw : String(range);
      return simplified.length < original.length ? simplified : range;
    };
  }
});

// node_modules/semver/ranges/subset.js
var require_subset = __commonJS({
  "node_modules/semver/ranges/subset.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var Comparator = require_comparator();
    var { ANY } = Comparator;
    var satisfies = require_satisfies();
    var compare = require_compare();
    var subset = (sub, dom, options = {}) => {
      if (sub === dom) {
        return true;
      }
      sub = new Range(sub, options);
      dom = new Range(dom, options);
      let sawNonNull = false;
      OUTER: for (const simpleSub of sub.set) {
        for (const simpleDom of dom.set) {
          const isSub = simpleSubset(simpleSub, simpleDom, options);
          sawNonNull = sawNonNull || isSub !== null;
          if (isSub) {
            continue OUTER;
          }
        }
        if (sawNonNull) {
          return false;
        }
      }
      return true;
    };
    var minimumVersionWithPreRelease = [new Comparator(">=0.0.0-0")];
    var minimumVersion = [new Comparator(">=0.0.0")];
    var simpleSubset = (sub, dom, options) => {
      if (sub === dom) {
        return true;
      }
      if (sub.length === 1 && sub[0].semver === ANY) {
        if (dom.length === 1 && dom[0].semver === ANY) {
          return true;
        } else if (options.includePrerelease) {
          sub = minimumVersionWithPreRelease;
        } else {
          sub = minimumVersion;
        }
      }
      if (dom.length === 1 && dom[0].semver === ANY) {
        if (options.includePrerelease) {
          return true;
        } else {
          dom = minimumVersion;
        }
      }
      const eqSet = /* @__PURE__ */ new Set();
      let gt, lt;
      for (const c of sub) {
        if (c.operator === ">" || c.operator === ">=") {
          gt = higherGT(gt, c, options);
        } else if (c.operator === "<" || c.operator === "<=") {
          lt = lowerLT(lt, c, options);
        } else {
          eqSet.add(c.semver);
        }
      }
      if (eqSet.size > 1) {
        return null;
      }
      let gtltComp;
      if (gt && lt) {
        gtltComp = compare(gt.semver, lt.semver, options);
        if (gtltComp > 0) {
          return null;
        } else if (gtltComp === 0 && (gt.operator !== ">=" || lt.operator !== "<=")) {
          return null;
        }
      }
      for (const eq of eqSet) {
        if (gt && !satisfies(eq, String(gt), options)) {
          return null;
        }
        if (lt && !satisfies(eq, String(lt), options)) {
          return null;
        }
        for (const c of dom) {
          if (!satisfies(eq, String(c), options)) {
            return false;
          }
        }
        return true;
      }
      let higher, lower;
      let hasDomLT, hasDomGT;
      let needDomLTPre = lt && !options.includePrerelease && lt.semver.prerelease.length ? lt.semver : false;
      let needDomGTPre = gt && !options.includePrerelease && gt.semver.prerelease.length ? gt.semver : false;
      if (needDomLTPre && needDomLTPre.prerelease.length === 1 && lt.operator === "<" && needDomLTPre.prerelease[0] === 0) {
        needDomLTPre = false;
      }
      for (const c of dom) {
        hasDomGT = hasDomGT || c.operator === ">" || c.operator === ">=";
        hasDomLT = hasDomLT || c.operator === "<" || c.operator === "<=";
        if (gt) {
          if (needDomGTPre) {
            if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomGTPre.major && c.semver.minor === needDomGTPre.minor && c.semver.patch === needDomGTPre.patch) {
              needDomGTPre = false;
            }
          }
          if (c.operator === ">" || c.operator === ">=") {
            higher = higherGT(gt, c, options);
            if (higher === c && higher !== gt) {
              return false;
            }
          } else if (gt.operator === ">=" && !c.test(gt.semver)) {
            return false;
          }
        }
        if (lt) {
          if (needDomLTPre) {
            if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomLTPre.major && c.semver.minor === needDomLTPre.minor && c.semver.patch === needDomLTPre.patch) {
              needDomLTPre = false;
            }
          }
          if (c.operator === "<" || c.operator === "<=") {
            lower = lowerLT(lt, c, options);
            if (lower === c && lower !== lt) {
              return false;
            }
          } else if (lt.operator === "<=" && !c.test(lt.semver)) {
            return false;
          }
        }
        if (!c.operator && (lt || gt) && gtltComp !== 0) {
          return false;
        }
      }
      if (gt && hasDomLT && !lt && gtltComp !== 0) {
        return false;
      }
      if (lt && hasDomGT && !gt && gtltComp !== 0) {
        return false;
      }
      if (needDomGTPre || needDomLTPre) {
        return false;
      }
      return true;
    };
    var higherGT = (a, b, options) => {
      if (!a) {
        return b;
      }
      const comp = compare(a.semver, b.semver, options);
      return comp > 0 ? a : comp < 0 ? b : b.operator === ">" && a.operator === ">=" ? b : a;
    };
    var lowerLT = (a, b, options) => {
      if (!a) {
        return b;
      }
      const comp = compare(a.semver, b.semver, options);
      return comp < 0 ? a : comp > 0 ? b : b.operator === "<" && a.operator === "<=" ? b : a;
    };
    module.exports = subset;
  }
});

// node_modules/semver/index.js
var require_semver2 = __commonJS({
  "node_modules/semver/index.js"(exports, module) {
    "use strict";
    var internalRe = require_re();
    var constants = require_constants();
    var SemVer = require_semver();
    var identifiers = require_identifiers();
    var parse = require_parse();
    var valid = require_valid();
    var clean = require_clean();
    var inc = require_inc();
    var diff = require_diff();
    var major = require_major();
    var minor = require_minor();
    var patch = require_patch();
    var prerelease = require_prerelease();
    var compare = require_compare();
    var rcompare = require_rcompare();
    var compareLoose = require_compare_loose();
    var compareBuild = require_compare_build();
    var sort = require_sort();
    var rsort = require_rsort();
    var gt = require_gt();
    var lt = require_lt();
    var eq = require_eq();
    var neq = require_neq();
    var gte = require_gte();
    var lte = require_lte();
    var cmp = require_cmp();
    var coerce = require_coerce();
    var truncate = require_truncate();
    var Comparator = require_comparator();
    var Range = require_range();
    var satisfies = require_satisfies();
    var toComparators = require_to_comparators();
    var maxSatisfying = require_max_satisfying();
    var minSatisfying = require_min_satisfying();
    var minVersion = require_min_version();
    var validRange = require_valid2();
    var outside = require_outside();
    var gtr = require_gtr();
    var ltr = require_ltr();
    var intersects = require_intersects();
    var simplifyRange = require_simplify();
    var subset = require_subset();
    module.exports = {
      parse,
      valid,
      clean,
      inc,
      diff,
      major,
      minor,
      patch,
      prerelease,
      compare,
      rcompare,
      compareLoose,
      compareBuild,
      sort,
      rsort,
      gt,
      lt,
      eq,
      neq,
      gte,
      lte,
      cmp,
      coerce,
      truncate,
      Comparator,
      Range,
      satisfies,
      toComparators,
      maxSatisfying,
      minSatisfying,
      minVersion,
      validRange,
      outside,
      gtr,
      ltr,
      intersects,
      simplifyRange,
      subset,
      SemVer,
      re: internalRe.re,
      src: internalRe.src,
      tokens: internalRe.t,
      SEMVER_SPEC_VERSION: constants.SEMVER_SPEC_VERSION,
      RELEASE_TYPES: constants.RELEASE_TYPES,
      compareIdentifiers: identifiers.compareIdentifiers,
      rcompareIdentifiers: identifiers.rcompareIdentifiers
    };
  }
});

// packages/cli/src/hook.ts
import { existsSync as existsSync2, readFileSync as readFileSync2 } from "node:fs";
import { join as join2 } from "node:path";

// packages/core/src/net/http.ts
var USER_AGENT = "botguard/0.1 (+https://github.com/Dhaxor/botguard)";
var HttpError = class extends Error {
  constructor(status, url, message) {
    super(message ?? `HTTP ${status} for ${url}`);
    this.status = status;
    this.url = url;
    this.name = "HttpError";
  }
};
var DEFAULT_TIMEOUT = 15e3;
var DEFAULT_MAX_BYTES = 50 * 1024 * 1024;
async function request(url, opts) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT);
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      headers: { "user-agent": USER_AGENT, ...opts.headers },
      body: opts.body,
      signal: controller.signal,
      redirect: "follow"
    });
    return res;
  } catch (err) {
    if (controller.signal.aborted) throw new Error(`Timed out fetching ${url}`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
async function readCapped(res, url, maxBytes) {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new Error(`${url} is too large (${declared} bytes)`);
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`${url} is too large (over ${maxBytes} bytes)`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}
async function fetchBytes(url, opts = {}) {
  const res = await request(url, opts);
  if (!res.ok) throw new HttpError(res.status, url);
  return readCapped(res, url, opts.maxBytes ?? DEFAULT_MAX_BYTES);
}
async function fetchJson(url, opts = {}) {
  const res = await request(url, {
    ...opts,
    headers: { accept: "application/json", ...opts.body ? { "content-type": "application/json" } : {}, ...opts.headers }
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new HttpError(res.status, url);
  const bytes = await readCapped(res, url, opts.maxBytes ?? DEFAULT_MAX_BYTES);
  return JSON.parse(new TextDecoder().decode(bytes));
}

// packages/core/src/registry/github.ts
function parseGithubRef(input) {
  const s = input.trim().replace(/^git\+/, "").replace(/\.git(?=$|[#/])/, "");
  const short = /^(?:github:)?([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]+?)(?:#(.+))?$/.exec(s);
  if (short && !s.includes("://") && !s.startsWith("@")) return { owner: short[1], repo: short[2], ref: short[3] };
  const m = /^(?:https?:\/\/|ssh:\/\/git@|git@)?(?:www\.)?github\.com[/:]([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\/(?:tree|blob|commit)\/([^/?#]+))?(?:[/?#].*)?$/i.exec(s);
  if (!m) return null;
  const hashRef = /#([^#]+)$/.exec(s)?.[1];
  return { owner: m[1], repo: m[2], ref: m[3] ?? hashRef };
}
function headers(token) {
  const t = token ?? process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  return {
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    ...t ? { authorization: `Bearer ${t}` } : {}
  };
}
async function getGithubRepo(ref, token) {
  return fetchJson(`https://api.github.com/repos/${ref.owner}/${ref.repo}`, { headers: headers(token), timeoutMs: 1e4 });
}
async function getGithubOwner(login, token) {
  return fetchJson(`https://api.github.com/users/${encodeURIComponent(login)}`, { headers: headers(token), timeoutMs: 8e3 });
}
async function fetchGithubRaw(ref, path, timeoutMs = 6e3) {
  const url = `https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${encodeURIComponent(ref.ref ?? "HEAD")}/${path}`;
  try {
    return new TextDecoder().decode(await fetchBytes(url, { timeoutMs, maxBytes: 2 * 1024 * 1024 }));
  } catch {
    return null;
  }
}

// packages/core/src/install/parse-command.ts
function splitCommands(line) {
  const commands = [];
  const pipes = [];
  let words = [];
  let cur = "";
  let quote = null;
  let hasWord = false;
  const pushWord = () => {
    if (hasWord) words.push(cur);
    cur = "";
    hasWord = false;
  };
  const pushCmd = (piped) => {
    pushWord();
    if (words.length) {
      commands.push(words);
      pipes.push(piped);
    }
    words = [];
  };
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && i + 1 < line.length) cur += line[++i];
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      hasWord = true;
    } else if (c === "\\" && i + 1 < line.length) {
      if (line[i + 1] === "\n") i++;
      else {
        cur += line[++i];
        hasWord = true;
      }
    } else if (c === " " || c === "	") pushWord();
    else if (c === "\n" || c === "\r" || c === ";") pushCmd(false);
    else if (c === "&" || c === "|") {
      const doubled = line[i + 1] === c;
      if (doubled) i++;
      pushCmd(c === "|" && !doubled);
    } else if (c === "(" || c === ")" || c === "{" || c === "}") pushWord();
    else {
      cur += c;
      hasWord = true;
    }
  }
  pushCmd(false);
  return commands.map((w, i) => ({ words: w, pipedTo: pipes[i] ? commands[i + 1] : void 0 }));
}
var WRAPPERS = /* @__PURE__ */ new Set(["sudo", "doas", "time", "nohup", "exec", "command", "env", "nice", "call", "start", "cmd", "/c"]);
var NPM_INSTALL = /* @__PURE__ */ new Set(["install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "ci", "update", "up", "upgrade"]);
var NPM_FLAGS_WITH_VALUE = /* @__PURE__ */ new Set(["--registry", "--prefix", "-C", "--cache", "--tag", "--workspace", "-w", "--filter", "--dir", "--userconfig", "--global-dir", "--cwd"]);
var PIP_FLAGS_WITH_VALUE = /* @__PURE__ */ new Set(["-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--prefix", "--root", "--python", "-f", "--find-links", "--platform", "--python-version", "--implementation", "--abi", "--src", "--upgrade-strategy", "--cache-dir", "--trusted-host", "--progress-bar", "--log", "--proxy", "--timeout", "--retries", "--group", "--with", "--from", "-p"]);
function stripWrappers(words) {
  let i = 0;
  while (i < words.length && (WRAPPERS.has(words[i]) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]))) i++;
  return words.slice(i);
}
function base(cmd) {
  return cmd.replace(/\\/g, "/").split("/").pop().replace(/\.(exe|cmd|bat|ps1)$/i, "").toLowerCase();
}
function npmSpecIntent(arg, executes, raw) {
  if (/^(?:\.{1,2}\/|\/|~\/|[A-Za-z]:[\\/]|file:|link:|workspace:)/.test(arg) || arg === ".") return null;
  if (/^https?:\/\/.+\.(?:tgz|tar\.gz)(?:[?#].*)?$/i.test(arg)) return { kind: "remote-archive", url: arg, ecosystem: "npm", raw };
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/(?:www\.)?github\.com)/i.test(arg) || /^[\w.-]+\/[\w.-]+(?:#.+)?$/.test(arg)) {
    const ref = parseGithubRef(arg);
    if (ref) return { kind: "repo", owner: ref.owner, repo: ref.repo, ref: ref.ref, url: `https://github.com/${ref.owner}/${ref.repo}`, raw };
    return null;
  }
  const alias = /^(?:@[^/@]+\/)?[^@]+@npm:((?:@[^/@]+\/)?[^@]+)(?:@(.+))?$/.exec(arg);
  if (alias) return { kind: "package", ecosystem: "npm", name: alias[1], spec: alias[2], executes, raw };
  const m = /^((?:@[a-z0-9][\w.-]*\/)?[a-z0-9~][\w.-]*)(?:@(.+))?$/i.exec(arg);
  if (!m) return null;
  return { kind: "package", ecosystem: "npm", name: m[1], spec: m[2], executes, raw };
}
function pipSpecIntent(arg, executes, raw) {
  if (/^(?:\.{1,2}[\\/]|\/|~\/|[A-Za-z]:[\\/])/.test(arg) || arg === ".") return null;
  const gitUrl = /^git\+(https?:\/\/[^@#\s]+?)(?:\.git)?(?:@([^#\s]+))?(?:#.*)?$/.exec(arg);
  if (gitUrl) {
    const ref = parseGithubRef(gitUrl[1]);
    if (ref) return { kind: "repo", owner: ref.owner, repo: ref.repo, ref: gitUrl[2], url: `https://github.com/${ref.owner}/${ref.repo}`, raw };
    return { kind: "remote-archive", url: gitUrl[1], ecosystem: "pypi", raw };
  }
  if (/^https?:\/\//i.test(arg)) return { kind: "remote-archive", url: arg, ecosystem: "pypi", raw };
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*((?:===?|~=|>=|<=|!=|>|<)[^;\s]*(?:,(?:===?|~=|>=|<=|!=|>|<)[^;\s]*)*)?/.exec(arg);
  if (!m) return null;
  return { kind: "package", ecosystem: "pypi", name: m[1], spec: m[2] || void 0, executes, raw };
}
function parseNpmFamily(tool, args, raw, out) {
  const execLike = tool === "npx" || tool === "pnpx" || tool === "bunx";
  let sub = execLike ? "exec" : args[0]?.toLowerCase();
  let rest = execLike ? args : args.slice(1);
  if (tool === "yarn" && (sub === void 0 || sub.startsWith("-"))) {
    out.push({ kind: "manifest", ecosystem: "npm", raw });
    return;
  }
  if (tool === "npm" && (sub === "exec" || sub === "x")) sub = "exec";
  if ((tool === "pnpm" || tool === "yarn") && sub === "dlx") sub = "exec";
  if (tool === "bun" && sub === "x") sub = "exec";
  if ((tool === "npm" || tool === "pnpm" || tool === "yarn" || tool === "bun") && (sub === "create" || sub === "init")) {
    const initializer = rest.find((a) => !a.startsWith("-"));
    if (!initializer) return;
    const name = initializer.startsWith("@") ? initializer.replace(/^(@[^/]+)(?:\/(.+))?$/, (_m, s, n) => `${s}/create${n ? `-${n}` : ""}`) : `create-${initializer.replace(/@.*$/, "")}`;
    out.push({ kind: "package", ecosystem: "npm", name, executes: true, raw });
    return;
  }
  const isInstall = sub !== void 0 && (NPM_INSTALL.has(sub) || tool === "bun" && sub === "a" || tool === "pnpm" && sub === "i");
  if (!isInstall && sub !== "exec") return;
  const positional = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--") {
      if (sub === "exec") break;
      continue;
    }
    if (a.startsWith("--registry=")) out.push({ kind: "custom-registry", registry: a.slice(11), ecosystem: "npm", raw });
    else if (a === "--registry" && rest[i + 1]) out.push({ kind: "custom-registry", registry: rest[i + 1], ecosystem: "npm", raw });
    if (a === "-p" || a === "--package") {
      if (rest[i + 1]) positional.push(rest[++i]);
      continue;
    }
    if (a.startsWith("--package=")) {
      positional.push(a.slice(10));
      continue;
    }
    if (a.startsWith("-")) {
      if (NPM_FLAGS_WITH_VALUE.has(a) && !a.includes("=")) i++;
      continue;
    }
    positional.push(a);
    if (sub === "exec") break;
  }
  if (sub === "exec") {
    const pkg = positional[0];
    if (pkg) {
      const intent = npmSpecIntent(pkg, true, raw);
      if (intent) out.push(intent);
    }
    return;
  }
  if (!positional.length) {
    if (sub === "install" || sub === "i" || sub === "ci" || tool === "bun" || tool === "pnpm") out.push({ kind: "manifest", ecosystem: "npm", raw });
    return;
  }
  for (const p of positional) {
    const intent = npmSpecIntent(p, false, raw);
    if (intent) out.push(intent);
  }
}
function parsePipArgs(args, raw, out, executes = false) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-r" || a === "--requirement") {
      if (args[i + 1]) out.push({ kind: "manifest", ecosystem: "pypi", file: args[++i], raw });
      continue;
    }
    if (a.startsWith("--requirement=") || /^-r\S/.test(a)) {
      out.push({ kind: "manifest", ecosystem: "pypi", file: a.replace(/^--requirement=|^-r/, ""), raw });
      continue;
    }
    if (a === "-i" || a === "--index-url" || a === "--extra-index-url") {
      const v = args[i + 1];
      if (v && !/pypi\.org\/simple/.test(v)) out.push({ kind: "custom-registry", registry: v, ecosystem: "pypi", raw });
      i++;
      continue;
    }
    if (/^--(?:extra-)?index-url=/.test(a)) {
      const v = a.split("=").slice(1).join("=");
      if (!/pypi\.org\/simple/.test(v)) out.push({ kind: "custom-registry", registry: v, ecosystem: "pypi", raw });
      continue;
    }
    if (a.startsWith("-")) {
      if (PIP_FLAGS_WITH_VALUE.has(a)) i++;
      continue;
    }
    const intent = pipSpecIntent(a, executes, raw);
    if (intent) out.push(intent);
  }
}
function parsePythonFamily(tool, args, raw, out) {
  if (tool === "pip" || /^pip\d/.test(tool)) {
    if (args[0] === "install" || args[0] === "download") parsePipArgs(args.slice(1), raw, out);
    return;
  }
  if (/^(?:python|py)\d?(?:\.\d+)?$/.test(tool)) {
    const m = args.indexOf("-m");
    if (m >= 0 && args[m + 1] === "pip" && args[m + 2] === "install") parsePipArgs(args.slice(m + 3), raw, out);
    return;
  }
  if (tool === "uv") {
    if (args[0] === "pip" && args[1] === "install") parsePipArgs(args.slice(2), raw, out);
    else if (args[0] === "add") parsePipArgs(args.slice(1), raw, out);
    else if (args[0] === "tool" && (args[1] === "install" || args[1] === "run")) parsePipArgs(args.slice(2, 3), raw, out, args[1] === "run");
    else if (args[0] === "run" && args.includes("--with")) parsePipArgs([args[args.indexOf("--with") + 1] ?? ""], raw, out);
    else if (args[0] === "sync") out.push({ kind: "manifest", ecosystem: "pypi", raw });
    return;
  }
  if (tool === "uvx") {
    const first = args.find((a) => !a.startsWith("-"));
    if (first) parsePipArgs([first], raw, out, true);
    return;
  }
  if (tool === "pipx" && (args[0] === "install" || args[0] === "run")) {
    const first = args.slice(1).find((a) => !a.startsWith("-"));
    if (first) parsePipArgs([first], raw, out, args[0] === "run");
    return;
  }
  if ((tool === "poetry" || tool === "pdm" || tool === "rye" || tool === "hatch") && args[0] === "add") parsePipArgs(args.slice(1), raw, out);
  else if ((tool === "poetry" || tool === "pdm") && args[0] === "install") out.push({ kind: "manifest", ecosystem: "pypi", raw });
}
function parseInstallCommand(command) {
  const out = [];
  for (const { words, pipedTo } of splitCommands(command)) {
    const w = stripWrappers(words);
    if (!w.length) continue;
    const tool = base(w[0]);
    const args = w.slice(1);
    const raw = w.join(" ").slice(0, 300);
    if (["npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx"].includes(tool)) parseNpmFamily(tool, args, raw, out);
    else if (/^(?:pip\d?(?:\.\d+)?|python\d?(?:\.\d+)?|py|uv|uvx|pipx|poetry|pdm|rye|hatch)$/.test(tool)) parsePythonFamily(tool, args, raw, out);
    else if (tool === "git" && args[0] === "clone") {
      const url = args.slice(1).find((a) => !a.startsWith("-") && /github\.com|^git@/.test(a));
      const ref = url ? parseGithubRef(url) : null;
      if (ref) out.push({ kind: "repo", owner: ref.owner, repo: ref.repo, ref: ref.ref, url: `https://github.com/${ref.owner}/${ref.repo}`, raw });
    } else if (tool === "gh" && args[0] === "repo" && args[1] === "clone" && args[2]) {
      const ref = parseGithubRef(args[2]);
      if (ref) out.push({ kind: "repo", owner: ref.owner, repo: ref.repo, url: `https://github.com/${ref.owner}/${ref.repo}`, raw });
    } else if (["curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"].includes(tool) && pipedTo) {
      const sink = base(stripWrappers(pipedTo)[0] ?? "");
      if (/^(?:ba|z|da|k)?sh$|^iex$|^invoke-expression$|^python\d?$|^node$|^pwsh$|^powershell$/.test(sink)) {
        out.push({ kind: "pipe-to-shell", url: args.find((a) => /^https?:\/\//i.test(a)), raw: `${raw} | ${sink}` });
      }
    }
  }
  return out;
}

// packages/core/src/install/check.ts
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

// packages/core/src/analyzers/text.ts
function langOf(path) {
  const p = path.toLowerCase();
  if (p.endsWith(".d.ts")) return void 0;
  if (/\.(m?[jt]sx?|c[jt]s)$/.test(p)) return "js";
  if (/\.(py|pyw)$/.test(p) || /(^|\/)setup$/.test(p)) return "py";
  if (/\.(sh|bash|zsh|ps1|psm1|bat|cmd|vbs)$/.test(p) || /(^|\/)(makefile|install)$/.test(p)) return "shell";
  if (p.endsWith(".sol")) return "sol";
  if (/\.(md|markdown|txt|rst|html?)$/.test(p) || /(^|\/)readme$/.test(p)) return "text";
  return void 0;
}
var LineIndex = class {
  constructor(text) {
    this.text = text;
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) this.starts.push(i + 1);
  }
  starts = [0];
  lineOf(index) {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = lo + hi + 1 >> 1;
      if (this.starts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }
  /** The matched line, trimmed to a window around the match for very long (minified) lines. */
  snippet(index, length) {
    const line = this.lineOf(index) - 1;
    const start = this.starts[line];
    const end = this.starts[line + 1] !== void 0 ? this.starts[line + 1] - 1 : this.text.length;
    let s = this.text.slice(start, end);
    let offset = index - start;
    if (s.length > 180) {
      const from = Math.max(0, offset - 60);
      s = (from > 0 ? "\u2026" : "") + s.slice(from, from + 170) + (from + 170 < s.length ? "\u2026" : "");
      offset = 0;
    }
    void length;
    return s.replace(/\t/g, "  ").trim();
  }
  evidence(file, index, length) {
    return { file, line: this.lineOf(index), snippet: this.snippet(index, length) };
  }
};

// packages/core/src/analyzers/manifest.ts
var INSTALL_HOOKS = ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"];
var BENIGN_SCRIPT = /^(?:husky(?: install)?|is-ci \|\| husky(?: install)?|patch-package|node-gyp rebuild|prebuild-install(?: \|\| node-gyp rebuild)?|node-gyp-build|ngcc|lerna bootstrap|npm run build|pnpm build|yarn build|tsc(?: -p \S+)?|prisma generate|svelte-kit sync|nuxt prepare|electron-builder install-app-deps|simple-git-hooks|lefthook install|opencollective-postinstall(?: \|\| true)?|node scripts\/postinstall\.js|exit 0|echo .*)$/;
var DANGEROUS_SCRIPT = /\bcurl\b|\bwget\b|powershell|Invoke-WebRequest|\biwr\b|certutil|bitsadmin|node\s+-e\b|node\s+--eval|python[0-9.]*\s+-c\b|base64\s+(?:-d|--decode)|\beval\b|\|\s*(?:ba)?sh\b|https?:\/\//i;
function dirOf(path) {
  const i = path.lastIndexOf("/");
  return i < 0 ? "" : path.slice(0, i + 1);
}
function normalize(path) {
  const out = [];
  for (const part of path.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return out.join("/");
}
function scriptTargets(script, base2) {
  const out = [];
  for (const m of script.matchAll(/\b(?:node|nodejs|bun|deno run|tsx|ts-node|python[0-9.]*|sh|bash|zsh|pwsh|powershell(?:\.exe)?(?:\s+-File)?)\s+(?:-\S+\s+)*["']?([\w./\\-]+\.(?:[cm]?js|ts|py|sh|ps1))/g)) {
    out.push(normalize(base2 + m[1].replace(/\\/g, "/")));
  }
  return out;
}
function urlOrGitSpec(spec) {
  return /^(?:https?:|git\+|git:|github:|gitlab:|bitbucket:|[\w.-]+\/[\w.-]+(?:#.*)?$)/.test(spec) && !spec.startsWith("npm:");
}
function analyzePackageJson(file, isRoot, result) {
  let pkg;
  try {
    pkg = JSON.parse(file.text);
  } catch {
    return;
  }
  const base2 = dirOf(file.path);
  const lines = new LineIndex(file.text);
  const scripts = pkg.scripts ?? {};
  for (const hook of INSTALL_HOOKS) {
    const script = scripts[hook];
    if (typeof script !== "string" || !script.trim()) continue;
    for (const t of scriptTargets(script, base2)) result.installTime.add(t);
    const at = file.text.indexOf(`"${hook}"`);
    const evidence = [at >= 0 ? lines.evidence(file.path, at, hook.length) : { file: file.path, snippet: `${hook}: ${script}` }];
    if (DANGEROUS_SCRIPT.test(script)) {
      result.findings.push({
        id: "manifest.install-script-download",
        severity: "high",
        category: "install-script",
        title: `"${hook}" script downloads or evaluates code during install`,
        detail: `npm runs this automatically: \`${script.slice(0, 160)}\`. Fetching or evaluating code at install time is how most npm malware triggers.`,
        evidence
      });
    } else if (!BENIGN_SCRIPT.test(script.trim())) {
      result.findings.push({
        id: "manifest.install-script",
        severity: isRoot ? "low" : "info",
        category: "install-script",
        title: `Runs a "${hook}" script automatically`,
        detail: `npm executes \`${script.slice(0, 160)}\` on install. The files it runs were scanned with extra suspicion.`,
        evidence
      });
    }
  }
  for (const field of ["dependencies", "optionalDependencies", "devDependencies", "peerDependencies"]) {
    const deps = pkg[field] ?? {};
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec !== "string") continue;
      if (spec.startsWith("workspace:") || spec.startsWith("file:") || spec.startsWith("link:")) continue;
      if (urlOrGitSpec(spec) && field !== "devDependencies") {
        const at = file.text.indexOf(`"${name}"`);
        result.findings.push({
          id: "manifest.url-dependency",
          severity: "medium",
          category: "install-script",
          title: "Depends on code fetched from a URL or git repo",
          detail: `"${name}": "${spec}" bypasses the npm registry, where packages are at least scanned and can be taken down.`,
          evidence: at >= 0 ? [lines.evidence(file.path, at, name.length)] : void 0
        });
        continue;
      }
      const alias = /^npm:(@?[^@]+)@?(.*)$/.exec(spec);
      result.dependencies.push({
        ecosystem: "npm",
        name: alias ? alias[1] : name,
        spec: alias ? alias[2] || void 0 : spec,
        source: file.path,
        direct: true
      });
    }
  }
}
function analyzeSetupPy(file, result) {
  result.installTime.add(file.path);
  const lines = new LineIndex(file.text);
  const cmd = /cmdclass\s*=|class\s+\w+\s*\(\s*(?:install|develop|egg_info|build_py|sdist|bdist_egg)\s*\)/.exec(file.text);
  if (cmd) {
    result.findings.push({
      id: "manifest.setup-cmdclass",
      severity: "low",
      category: "install-script",
      title: "setup.py overrides install commands",
      detail: "Custom install/develop/egg_info commands run arbitrary Python during `pip install`. setup.py was scanned with extra suspicion.",
      evidence: [lines.evidence(file.path, cmd.index, cmd[0].length)]
    });
  }
  for (const m of file.text.matchAll(/install_requires\s*=\s*\[([^\]]*)\]/g)) {
    for (const req of quotedStrings(m[1])) pushRequirement(req, file.path, result);
  }
}
function quotedStrings(list) {
  return [...list.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map((m) => (m[1] ?? m[2] ?? "").replace(/\\"/g, '"'));
}
function pushRequirement(line, source, result) {
  const clean = line.replace(/\s+#.*$/, "").trim();
  if (!clean || clean.startsWith("#") || clean.startsWith("-")) return;
  if (/^(?:git\+|https?:)/.test(clean) || clean.includes(" @ ")) {
    result.findings.push({
      id: "manifest.url-requirement",
      severity: "low",
      category: "install-script",
      title: "Installs a Python dependency from a URL",
      detail: `\`${clean.slice(0, 160)}\` skips PyPI, so nothing vets what gets downloaded.`,
      evidence: [{ file: source, snippet: clean.slice(0, 160) }]
    });
    return;
  }
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*((?:[<>=!~]=?|===)\s*[^;\s]+(?:\s*,\s*(?:[<>=!~]=?|===)\s*[^;\s]+)*)?/.exec(clean);
  if (!m) return;
  const spec = m[2]?.replace(/\s+/g, "");
  const exact = spec && /^===?([^,*]+)$/.exec(spec);
  result.dependencies.push({ ecosystem: "pypi", name: m[1], spec, version: exact ? exact[1] : void 0, source, direct: true });
}
function analyzeRequirements(file, result) {
  const lines = new LineIndex(file.text);
  for (const m of file.text.matchAll(/^\s*(?:--(?:extra-)?index-url|-i)\s+(\S+)/gm)) {
    if (/pypi\.org\/simple/.test(m[1])) continue;
    result.findings.push({
      id: "manifest.custom-index",
      severity: "medium",
      category: "install-script",
      title: "Pulls packages from a non-PyPI index",
      detail: `pip will consult ${m[1]} as well as or instead of PyPI. Attackers use extra indexes for dependency-confusion attacks.`,
      evidence: [lines.evidence(file.path, m.index, m[0].length)]
    });
  }
  for (const line of file.text.split(/\r?\n/)) pushRequirement(line, file.path, result);
}
function analyzePyproject(file, result) {
  const deps = /^\s*dependencies\s*=\s*\[(.*)\]\s*$/m.exec(file.text) ?? /^\s*dependencies\s*=\s*\[\s*$([\s\S]*?)^\s*\]/m.exec(file.text);
  if (deps) for (const req of quotedStrings(deps[1])) pushRequirement(req, file.path, result);
  const poetry = /\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/.exec(file.text);
  if (poetry) {
    for (const m of poetry[1].matchAll(/^\s*([A-Za-z0-9][\w.-]*)\s*=/gm)) {
      if (m[1].toLowerCase() !== "python") result.dependencies.push({ ecosystem: "pypi", name: m[1], source: file.path, direct: true });
    }
  }
}
function analyzePth(file, result) {
  const m = /^\s*import\s.+$/m.exec(file.text);
  if (!m) return;
  result.findings.push({
    id: "manifest.pth-autorun",
    severity: "high",
    category: "persistence",
    title: "Ships a .pth file that runs code on every Python start",
    detail: "Lines starting with `import` in a .pth file execute whenever any Python program starts, a known way for malicious packages to stay active.",
    evidence: [new LineIndex(file.text).evidence(file.path, m.index, m[0].length)]
  });
}
function analyzePackageLock(file, result) {
  let lock;
  try {
    lock = JSON.parse(file.text);
  } catch {
    return;
  }
  if (lock.packages) {
    for (const [key2, info] of Object.entries(lock.packages)) {
      const i = key2.lastIndexOf("node_modules/");
      if (i < 0 || !info?.version) continue;
      result.dependencies.push({ ecosystem: "npm", name: key2.slice(i + 13), version: info.version, source: file.path, direct: false });
    }
    return;
  }
  const walk = (deps) => {
    for (const [name, raw] of Object.entries(deps ?? {})) {
      const info = raw;
      if (info?.version && !/^(?:file|link|git)/.test(info.version)) {
        result.dependencies.push({ ecosystem: "npm", name, version: info.version, source: file.path, direct: false });
      }
      walk(info?.dependencies);
    }
  };
  walk(lock.dependencies);
}
function analyzeYarnLock(file, result) {
  for (const m of file.text.matchAll(/^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:?\s+"?([^"\s]+)"?/gm)) {
    result.dependencies.push({ ecosystem: "npm", name: m[1], version: m[2], source: file.path, direct: false });
  }
}
function analyzePnpmLock(file, result) {
  for (const m of file.text.matchAll(/^\s{2}'?\/?(@?[^@\s'/][^@\s']*(?:\/[^@\s']+)?)@(\d[^:'\s(]*)/gm)) {
    result.dependencies.push({ ecosystem: "npm", name: m[1], version: m[2], source: file.path, direct: false });
  }
}
function analyzePoetryLock(file, result) {
  for (const m of file.text.matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g)) {
    result.dependencies.push({ ecosystem: "pypi", name: m[1], version: m[2], source: file.path, direct: false });
  }
}
function analyzeManifests(files) {
  const result = { findings: [], dependencies: [], installTime: /* @__PURE__ */ new Set() };
  for (const file of files) {
    const name = file.path.split("/").pop().toLowerCase();
    if (name === "package.json") analyzePackageJson(file, !file.path.includes("/"), result);
    else if (name === "setup.py") analyzeSetupPy(file, result);
    else if (/^requirements[^/]*\.(txt|in)$/.test(name)) analyzeRequirements(file, result);
    else if (name === "pyproject.toml") analyzePyproject(file, result);
    else if (name.endsWith(".pth")) analyzePth(file, result);
    else if (name === "package-lock.json" || name === "npm-shrinkwrap.json") analyzePackageLock(file, result);
    else if (name === "yarn.lock") analyzeYarnLock(file, result);
    else if (name === "pnpm-lock.yaml") analyzePnpmLock(file, result);
    else if (name === "poetry.lock") analyzePoetryLock(file, result);
  }
  return result;
}

// packages/core/src/analyzers/repo.ts
var DAY = 864e5;
function daysSince(iso, now = Date.now()) {
  if (!iso) return void 0;
  const t = typeof iso === "string" ? Date.parse(iso) : iso.getTime();
  return Number.isNaN(t) ? void 0 : Math.floor((now - t) / DAY);
}
function starBurst(times) {
  if (times.length < 10) return 0;
  const t = times.map((d) => d.getTime()).sort((a, b) => a - b);
  let best = 0;
  let lo = 0;
  for (let hi = 0; hi < t.length; hi++) {
    while (t[hi] - t[lo] > 2 * DAY) lo++;
    best = Math.max(best, hi - lo + 1);
  }
  return best / t.length;
}
var BOT_WORDS = /\b(?:bot|mev|front[- ]?run|sniper|arbitrage|copy[- ]?trad|polymarket|kalshi|hyperliquid|pump\.?fun|drainer|wallet)\b/i;
var DOCS_OR_SOURCE = /(?:^|[-_.])(?:docs?|sphinx|html|manual|source|src)(?:[-_.]|$)/i;
function repoSignals(input) {
  const { repo, owner } = input;
  const findings = [];
  const age = daysSince(repo.created_at) ?? 9999;
  const ownerAge = daysSince(owner?.created_at);
  const about = `${repo.full_name} ${repo.description ?? ""} ${(repo.topics ?? []).join(" ")}`;
  const isBotish = BOT_WORDS.test(about);
  const link = { url: repo.html_url };
  if (/\bdrainer\b/i.test(about)) {
    findings.push({
      id: "repo.drainer",
      severity: "high",
      category: "repo",
      title: "Describes itself as a drainer",
      detail: "The repository name/description mentions a drainer, i.e. a tool built to empty other people's wallets.",
      evidence: [{ ...link, snippet: repo.description ?? repo.full_name }]
    });
  }
  if (input.starTimes && repo.stargazers_count >= 20) {
    const burst = starBurst(input.starTimes);
    if (burst >= 0.6 && age < 180) {
      findings.push({
        id: "repo.star-burst",
        severity: "high",
        category: "repo",
        title: `${Math.round(burst * 100)}% of its early stars arrived within 48 hours`,
        detail: `Bought or bot-generated stars make a fresh repo look trusted. ${repo.stargazers_count} stars on a ${age}-day-old repository, mostly in one burst, fits that pattern. Malicious "Polymarket bot" repos in 2026 used exactly this trick.`,
        evidence: [link]
      });
    }
  }
  if (age < 30 && repo.stargazers_count >= 150) {
    findings.push({
      id: "repo.young-popular",
      severity: "medium",
      category: "repo",
      title: `${repo.stargazers_count} stars in ${age} days`,
      detail: "Very fast star growth on a brand-new repository is common for scam repos boosted with fake accounts.",
      evidence: [link]
    });
  }
  if (age < 14) {
    findings.push({
      id: "repo.new",
      severity: isBotish ? "low" : "info",
      category: "repo",
      title: `Repository is only ${age} day${age === 1 ? "" : "s"} old`,
      detail: "New repositories haven't had time to be reviewed or reported by others.",
      evidence: [link]
    });
  }
  if (ownerAge !== void 0 && ownerAge < 30) {
    findings.push({
      id: "repo.new-owner",
      severity: "medium",
      category: "repo",
      title: `Owner account created ${ownerAge} day${ownerAge === 1 ? "" : "s"} ago`,
      detail: "Throwaway GitHub accounts are a staple of malware campaigns: when one gets banned, the next one is ready.",
      evidence: [{ url: `https://github.com/${repo.owner.login}` }]
    });
  }
  if (!repo.has_issues && isBotish) {
    findings.push({
      id: "repo.issues-disabled",
      severity: "low",
      category: "repo",
      title: "Issues are disabled",
      detail: "Victims of malicious repos usually warn others in the issues. With issues off, nobody can.",
      evidence: [link]
    });
  }
  if (repo.forks_count > repo.stargazers_count * 1.5 && repo.forks_count >= 30 && age < 90) {
    findings.push({
      id: "repo.fork-inflation",
      severity: "low",
      category: "repo",
      title: "More forks than stars on a young repo",
      detail: "Fork counts are easy to inflate with bot accounts and are often used alongside fake stars.",
      evidence: [link]
    });
  }
  const shipped = (input.assets ?? []).filter(
    (a) => /\.(exe|scr|msi|dmg|pkg|apk|bat|cmd|vbs|jar|zip|rar|7z)$/i.test(a.name) && !DOCS_OR_SOURCE.test(a.name)
  );
  if (shipped.length && isBotish) {
    const established = owner?.type === "Organization" && (ownerAge ?? 0) > 2 * 365;
    findings.push({
      id: "repo.release-binaries",
      severity: established ? "low" : "medium",
      category: "repo",
      title: "Releases ship executables or archives",
      detail: `Releases include ${shipped.map((a) => a.name).slice(0, 3).join(", ")}. A downloaded bot binary can do anything; the source in the repo may not match it.`,
      evidence: [link]
    });
  }
  return findings;
}

// packages/core/src/intel/known-addresses.ts
var KNOWN_ADDRESSES = {
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
  "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
  "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router (v4)",
  "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router (old)",
  "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
  "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap Router (BSC)",
  "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Router v5",
  "0x111111125421ca6dc452d289314280a0f8842a65": "1inch Router v6",
  "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
  "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e": "Polymarket CTF Exchange",
  "0xc5d563a36ae78145c45a50134d48a1215220f80a": "Polymarket Neg Risk CTF Exchange",
  "0xd91e80cf2e7be2e162c6513ced06f1dd0da35296": "Polymarket Neg Risk Adapter",
  "0x4d97dcd97ec945f40cf65f87097ace5ea0476045": "Polymarket Conditional Tokens",
  "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": "USDC.e (Polygon)",
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
  JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4: "Jupiter Aggregator v6",
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": "Raydium AMM v4",
  "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": "pump.fun program",
  "11111111111111111111111111111111": "Solana System Program",
  TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA: "SPL Token Program"
};
function labelAddress(addr) {
  return KNOWN_ADDRESSES[addr] ?? KNOWN_ADDRESSES[addr.toLowerCase()];
}

// packages/core/src/analyzers/rules.ts
var CODE = ["js", "py", "shell"];
var SECRET_NAME = String.raw`\w*(?:PRIVATE_?KEY|MNEMONIC|SEED_?PHRASE|SECRET_?KEY)\w*|CLOB_(?:API_KEY|SECRET|PASS_?PHRASE)|POLY_(?:API_KEY|SECRET|PASS_?PHRASE)`;
var WALLET_EXTENSION_IDS = [
  "nkbihfbeogaeaoehlefnkodbefgpgknn",
  // MetaMask
  "bfnaelmomeimhlpmgjnjophhpkkoljpa",
  // Phantom
  "hnfanknocfeofbddgcijnmhnfnkdnaad",
  // Coinbase Wallet
  "acmacodkjbdgmoleebolmdjonilkdbch",
  // Rabby
  "mcohilncbfahbmgdjkbpemcciiolgcge",
  // OKX Wallet
  "bhhhlbepdkbapadjdnnojkbgioiodbic",
  // Solflare
  "ibnejdfjmmkpcnlpebklmnkoeoihofec",
  // TronLink
  "fhbohimaelbohpjbbldcngcnapndodjp",
  // Binance Wallet
  "egjidjbpglichdcondbcbdnbeeppgdph",
  // Trust Wallet
  "aholpfdialjgjfhomihkjbmgjidlcdno",
  // Exodus Web3
  "dmkamcknogkgcdfhhbddcghachkejeap",
  // Keplr
  "ejbalbakoplchlghecdalmeeeajnimhm"
  // MetaMask (Edge)
];
var TRUSTED_INSTALL_HOSTS = /\b(?:sh\.rustup\.rs|rustup\.rs|get\.docker\.com|deb\.nodesource\.com|rpm\.nodesource\.com|raw\.githubusercontent\.com\/(?:nvm-sh|Homebrew|foundry-rs|coral-xyz|solana-labs|anza-xyz)|install\.python-poetry\.org|astral\.sh|bun\.sh|foundry\.paradigm\.xyz|release\.solana\.com|release\.anza\.xyz|deno\.land|get\.pnpm\.io|claude\.ai\/install|starship\.rs|pyenv\.run|get\.helm\.sh|ollama\.com\/install|fnm\.vercel\.app|install\.determinate\.systems|sdk\.cloud\.google\.com|awscli\.amazonaws\.com|cli\.github\.com|tailscale\.com\/install|get\.k3s\.io)/i;
function isPublicIp(url) {
  const m = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/.exec(url);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if ([a, b, Number(m[3]), Number(m[4])].some((n) => n > 255)) return false;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 192 && b === 0 && Number(m[3]) === 2 || a === 198 && b === 51 && Number(m[3]) === 100 || a === 203 && b === 0 && Number(m[3]) === 113) return false;
  if (m[0] === "1.2.3.4") return false;
  return true;
}
var SECRET_VALUE = new RegExp(
  String.raw`(?:${SECRET_NAME}|\bprivateKey\b|\bprivate_key\b|\bmnemonic\b|\bseedPhrase\b|\bseed_phrase\b)`,
  "g"
);
var SIGNING_CONTEXT = /createHmac|hmac|sign|Signature|signer|derive|keccak|sha256|encrypt/i;
function secretSentInArgs(args) {
  for (const m of args.matchAll(SECRET_VALUE)) {
    const before = args.slice(Math.max(0, m.index - 60), m.index);
    if (!SIGNING_CONTEXT.test(before)) return true;
  }
  return false;
}
function isUnknownRecipient(match) {
  const addr = /0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44}/.exec(match)?.[0];
  return !addr || !labelAddress(addr);
}
var RULES = [
  // ---- secrets -------------------------------------------------------------------------------
  {
    id: "env-dump",
    langs: ["js"],
    re: /JSON\.stringify\(\s*(?:\{\s*\.\.\.\s*)?process\.env\s*\}?\s*[,)]/g,
    tags: ["secret-dump"]
  },
  {
    id: "py-env-dump",
    langs: ["py"],
    re: /json\.dumps\(\s*(?:dict\()?\s*os\.environ\b|str\(\s*os\.environ\s*\)|dict\(\s*os\.environ\s*\)\s*\)/g,
    tags: ["secret-dump"]
  },
  {
    id: "dotenv-raw-read",
    langs: ["js"],
    re: /read(?:File|FileSync)\s*\([^)\n]{0,120}?['"`][^'"`\n]*[\\/]?\.env(?:\.local|\.production)?['"`]/g,
    tags: ["dotenv-raw"]
  },
  {
    id: "py-dotenv-raw-read",
    langs: ["py"],
    re: /open\(\s*(?:f?['"][^'"\n]*[\\/]?\.env['"]|os\.path\.join\([^)\n]*['"]\.env['"]\))/g,
    tags: ["dotenv-raw"]
  },
  {
    id: "private-key-var",
    langs: ["js", "py"],
    re: new RegExp(
      String.raw`process\.env(?:\.|\[['"])(?:${SECRET_NAME})|os\.(?:getenv|environ\.get)\(\s*['"](?:${SECRET_NAME})['"]|os\.environ\[\s*['"](?:${SECRET_NAME})['"]\s*\]`,
      "g"
    ),
    tags: ["pk"]
  },
  {
    id: "secret-in-request",
    langs: ["js", "py"],
    re: /(?:(?<![\w.])fetch|\baxios(?:\.(?:post|put|get|request))?|\bgot(?:\.post)?|\bhttps?\.request|\brequests\.(?:post|put|get)|\bhttpx\.(?:post|put|get))\s*\(/g,
    argsTest: secretSentInArgs,
    tags: ["pk-sent", "net"],
    alone: {
      severity: "high",
      category: "exfiltration",
      title: "Sends a private key or seed phrase in a network request",
      detail: "A private key, mnemonic or API secret appears inside the arguments of an HTTP call. Bots sign locally; they never need to send your key anywhere.",
      advice: "Do not run this with a real wallet. If you did, move funds to a new wallet from a clean device."
    }
  },
  {
    id: "ssh-keys",
    langs: CODE,
    re: /\.ssh[\\/]+(?:id_\w+|authorized_keys|config)\b|['"`]id_(?:rsa|ed25519|ecdsa)['"`]/g,
    tags: ["cred-files"],
    alone: {
      severity: "medium",
      category: "secrets",
      title: "Reads SSH keys",
      detail: "The code references private SSH key files. A trading bot has no reason to touch them; stealers grab them to break into your servers and GitHub."
    }
  },
  {
    id: "cloud-credentials",
    langs: CODE,
    re: /\.aws[\\/]+credentials|['"`/\\]\.npmrc['"`]|\.git-credentials|\.docker[\\/]+config\.json|\.kube[\\/]+config|\.config[\\/]+gcloud|['"`/\\]\.pypirc['"`]/g,
    tags: ["cred-files"],
    alone: {
      severity: "medium",
      category: "secrets",
      title: "Reads cloud or registry credentials",
      detail: "The code references credential files (AWS, npm, Docker, Kubernetes, PyPI). Malware collects these to take over accounts and publish more malware."
    }
  },
  {
    id: "wallet-files",
    langs: CODE,
    re: /wallet\.dat\b|Electrum[\\/]+wallets|[\\/]Exodus[\\/]+exodus\.wallet|atomic[\\/]+Local Storage|Ethereum[\\/]+keystore|keystore[\\/]+UTC--/gi,
    tags: ["harvest"],
    alone: {
      severity: "high",
      category: "wallet",
      title: "Looks for desktop wallet files",
      detail: "The code references storage of desktop wallets (Bitcoin Core, Electrum, Exodus, Atomic, keystores). This is a hallmark of crypto stealers."
    }
  },
  {
    id: "wallet-extensions",
    langs: CODE,
    re: new RegExp(`Local Extension Settings|${WALLET_EXTENSION_IDS.join("|")}`, "g"),
    tags: ["harvest"],
    alone: {
      severity: "high",
      category: "wallet",
      title: "Targets browser wallet extensions",
      detail: "The code references the storage of browser wallet extensions such as MetaMask or Phantom. No trading bot needs this; wallet stealers do."
    }
  },
  {
    id: "browser-data",
    langs: CODE,
    re: /['"`][^'"`\n]{0,80}(?:Login Data|Local State|Web Data)['"`]|(?:Google[\\/]+Chrome|BraveSoftware|Microsoft[\\/]+Edge|Opera Software|Mozilla[\\/]+Firefox)[\\/]+(?:User Data|Profiles)|CryptUnprotectData|\bbrowser_cookie3\b|\bwin32crypt\b/g,
    tags: ["harvest"],
    alone: {
      severity: "high",
      category: "secrets",
      title: "Reads browser passwords or cookies",
      detail: "The code reaches into browser profile data (saved passwords, cookies, encryption keys). This is what info-stealers do."
    }
  },
  {
    id: "messenger-sessions",
    langs: CODE,
    re: /Telegram Desktop[\\/]+tdata|[\\/]tdata[\\/]+|discord(?:canary|ptb)?[\\/]+Local Storage[\\/]+leveldb/gi,
    tags: ["harvest"],
    alone: {
      severity: "high",
      category: "secrets",
      title: "Steals Telegram or Discord sessions",
      detail: "The code references Telegram Desktop's tdata folder or Discord's token storage, which lets an attacker log in as you."
    }
  },
  // ---- network ---------------------------------------------------------------------------------
  {
    id: "net",
    langs: ["js"],
    re: /(?<![\w.])fetch\s*\(|\baxios(?:\.(?:get|post|put|request|create))?\s*\(|\bhttps?\.(?:request|get)\s*\(|\bnew\s+XMLHttpRequest\b|\bgot(?:\.(?:get|post))?\s*\(|\bnet\.(?:connect|createConnection)\s*\(|\bnew\s+WebSocket\s*\(|\bundici\.(?:request|fetch)\s*\(/g,
    tags: ["net"]
  },
  {
    id: "py-net",
    langs: ["py"],
    re: /\brequests\.(?:post|put|get|request|Session)\b|\burllib\.request\.(?:urlopen|Request)\b|\bhttpx\.(?:post|put|get|AsyncClient|Client)\b|\baiohttp\.ClientSession\b|\bsocket\.socket\s*\(|\bhttp\.client\.HTTPS?Connection\b/g,
    tags: ["net"]
  },
  {
    id: "notify-endpoint",
    langs: CODE,
    re: /api\.telegram\.org\/bot|discord(?:app)?\.com\/api\/webhooks\/|hooks\.slack\.com\/services\//g,
    tags: ["net-notify", "net"]
  },
  {
    id: "collector-endpoint",
    langs: CODE,
    re: /webhook\.site|requestbin|pipedream\.net|\.oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator|canarytokens|ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|\bloca\.lt\b/gi,
    tags: ["net-bad", "net"],
    alone: {
      severity: "high",
      category: "exfiltration",
      title: "Talks to a throwaway collector or tunnel",
      detail: "The code contacts a request-collector or tunnelling service (webhook.site, ngrok, interactsh...). Attackers use these to receive stolen data without owning a server."
    }
  },
  {
    id: "file-host-endpoint",
    langs: CODE,
    re: /pastebin\.com\/(?:raw|api)|paste\.ee\/|hastebin\.com|transfer\.sh|gofile\.io|\bfile\.io\b|catbox\.moe|anonfiles|pixeldrain\.com|\btemp\.sh\b|bashupload\.com|\b0x0\.st\b/gi,
    tags: ["net-bad", "net"],
    alone: {
      severity: "medium",
      category: "exfiltration",
      title: "Uses a paste or anonymous file host",
      detail: "The code reads from or uploads to an anonymous paste/file host. Malware uses these to fetch second-stage payloads or dump stolen files."
    }
  },
  {
    id: "raw-ip-url",
    langs: CODE,
    re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/g,
    tags: ["net-bad", "net"],
    accept: isPublicIp,
    alone: {
      severity: "medium",
      category: "exfiltration",
      title: "Connects to a hard-coded IP address",
      detail: "The code calls a server by raw public IP instead of a domain name, a common way to hide a command-and-control server."
    }
  },
  {
    id: "dark-host",
    langs: CODE,
    re: /[a-z2-7]{16,56}\.onion\b|\.duckdns\.org|\.ddns\.net|\.no-ip\.(?:org|biz|com)/gi,
    tags: ["net-bad", "net"],
    alone: {
      severity: "medium",
      category: "exfiltration",
      title: "Uses Tor or dynamic-DNS hosts",
      detail: "Onion services and dynamic-DNS names hide who runs the server. Legitimate exchange and RPC endpoints never need them."
    }
  },
  // ---- execution -------------------------------------------------------------------------------
  {
    id: "child-process",
    langs: ["js"],
    re: /require\(\s*['"`](?:node:)?child_process['"`]\s*\)|from\s+['"`](?:node:)?child_process['"`]/g,
    tags: ["exec"]
  },
  {
    id: "py-process",
    langs: ["py"],
    re: /\bimport\s+subprocess\b|\bfrom\s+subprocess\s+import\b|\bos\.system\s*\(|\bos\.popen\s*\(|\bpty\.spawn\s*\(/g,
    tags: ["exec"]
  },
  {
    id: "download-and-run",
    langs: CODE,
    re: /\b(?:curl|wget)\b[^\n|;&]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,200}\|\s*(?:iex|Invoke-Expression)\b|\bIEX\s*\(\s*\(?\s*New-Object\s+(?:System\.)?Net\.WebClient|\.DownloadString\s*\(|certutil(?:\.exe)?\s+-urlcache|bitsadmin(?:\.exe)?\s+\/transfer|mshta(?:\.exe)?\s+https?:|powershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/gi,
    tags: ["exec", "net"],
    accept: (m) => !TRUSTED_INSTALL_HOSTS.test(m),
    alone: {
      severity: "high",
      category: "execution",
      title: "Downloads and runs a remote script",
      detail: "It pipes something from the internet straight into a shell or PowerShell. Whatever that server sends at the time runs with your permissions."
    }
  },
  {
    id: "eval",
    langs: ["js"],
    re: /(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]return\s+this|\bvm\.runIn(?:New|This)?Context\s*\(|\bnew\s+vm\.Script\s*\(/g,
    tags: ["eval"]
  },
  {
    id: "py-eval",
    langs: ["py"],
    re: /(?<![\w.])(?:exec|eval)\s*\(|\b__import__\s*\(\s*['"](?:base64|zlib|marshal|codecs)['"]/g,
    tags: ["eval"]
  },
  {
    id: "py-exec-payload",
    langs: ["py"],
    re: /(?<![\w.])exec\s*\(\s*(?:base64\.\w*decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|bz2\.decompress|lzma\.decompress|__import__\(\s*['"](?:base64|zlib|marshal|codecs)['"]\))/g,
    tags: ["eval", "decode"],
    alone: {
      severity: "high",
      category: "obfuscation",
      title: "Executes a hidden, encoded payload",
      detail: "It decodes a blob (base64/zlib/marshal) and runs it with exec(). This is how Python malware hides what it really does."
    }
  },
  // ---- obfuscation -----------------------------------------------------------------------------
  {
    id: "encoded-blob",
    langs: ["js", "py"],
    re: /Buffer\.from\(\s*['"`][A-Za-z0-9+/=]{160,}['"`]\s*,\s*['"`]base64['"`]|\batob\(\s*['"`][A-Za-z0-9+/=]{160,}|['"`](?:[0-9a-fA-F]{2}){200,}['"`]|String\.fromCharCode\((?:\s*\d+\s*,){24,}|(?:\\x[0-9a-fA-F]{2}){48,}|\b(?:base64\.b64decode|zlib\.decompress|marshal\.loads)\(\s*b?['"][A-Za-z0-9+/=]{160,}/g,
    tags: ["decode"]
  },
  {
    id: "js-obfuscator",
    langs: ["js"],
    re: /\b_0x[0-9a-f]{4,6}\b/g,
    minCount: 40,
    tags: ["obf"],
    alone: {
      severity: "medium",
      category: "obfuscation",
      title: "Code is deliberately obfuscated",
      detail: "Identifiers like _0x4f2a come from a JavaScript obfuscator. Open-source bots have no reason to hide their logic; malware does."
    }
  },
  {
    id: "pyarmor",
    langs: ["py"],
    re: /\bpyarmor_runtime\w*|__pyarmor__|\bPyArmor\b/g,
    tags: ["obf"],
    alone: {
      severity: "medium",
      category: "obfuscation",
      title: "Python code is packed with PyArmor",
      detail: "PyArmor hides the real source. Some commercial tools use it, but an obfuscated 'free bot' that handles your keys cannot be reviewed."
    }
  },
  // ---- persistence & evasion -------------------------------------------------------------------
  {
    id: "ssh-backdoor",
    langs: CODE,
    re: /(?:appendFile(?:Sync)?|writeFile(?:Sync)?|createWriteStream|open)\s*\([^\n]{0,200}?authorized_keys|>>\s*\S*authorized_keys/g,
    tags: ["exec"],
    alone: {
      severity: "critical",
      category: "persistence",
      title: "Installs an SSH backdoor",
      detail: "It writes to authorized_keys, giving the attacker permanent remote login to your machine.",
      advice: "Treat the machine as compromised: remove unknown keys from ~/.ssh/authorized_keys and rotate every secret it held."
    }
  },
  {
    id: "autostart",
    langs: CODE,
    re: /crontab\s+-|\/etc\/cron\.|\\CurrentVersion\\Run\b|Start Menu\\\\?Programs\\\\?Startup|schtasks(?:\.exe)?\s+\/create|launchctl\s+load|Library\/LaunchAgents|systemctl\s+(?:--user\s+)?enable/gi,
    tags: ["exec"],
    alone: {
      severity: "high",
      category: "persistence",
      title: "Makes itself start automatically",
      detail: "It registers a cron job, startup entry, scheduled task or launch agent so it keeps running after a reboot."
    }
  },
  {
    id: "sandbox-evasion",
    langs: CODE,
    re: /\b(?:vmware|virtualbox|vboxservice|qemu-ga|sandboxie|wireshark|procmon|ollydbg|x64dbg|ida64|fiddler|httpdebugger)\b/gi,
    minCount: 3,
    tags: [],
    alone: {
      severity: "medium",
      category: "obfuscation",
      title: "Checks for analysis tools or virtual machines",
      detail: "It looks for debuggers, VMs or network sniffers, usually so it can stay quiet while a researcher is watching."
    }
  },
  // ---- wallets ---------------------------------------------------------------------------------
  {
    id: "clipboard",
    langs: CODE,
    re: /\bclipboardy\b|navigator\.clipboard\.(?:read|write)|\bpbpaste\b|\bxclip\b|\bxsel\b|Get-Clipboard|Set-Clipboard|\bpyperclip\b|clipboard\.(?:read|write)Text/g,
    tags: ["clipboard"]
  },
  {
    id: "address-regex",
    langs: CODE,
    re: /0x\[(?:a-fA-F0-9|0-9a-fA-F|a-f0-9|0-9a-f)\]\{40\}|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|bc1\[|\[1-9A-HJ-NP-Za-km-z\]\{3[2-9]/g,
    tags: ["addr-regex"]
  },
  {
    id: "hardcoded-recipient",
    langs: ["js", "py"],
    re: /\bto\s*:\s*['"`]0x[0-9a-fA-F]{40}['"`]|['"]to['"]\s*:\s*['"]0x[0-9a-fA-F]{40}['"]|\.transfer\(\s*['"`]0x[0-9a-fA-F]{40}['"`]|toPubkey\s*:\s*new\s+PublicKey\(\s*['"`][1-9A-HJ-NP-Za-km-z]{32,44}['"`]|to_pubkey\s*=\s*(?:Pubkey|PublicKey)\.from_string\(\s*['"][1-9A-HJ-NP-Za-km-z]{32,44}['"]/g,
    tags: ["transfer-hardcoded"],
    accept: isUnknownRecipient
  },
  {
    id: "balance-sweep",
    langs: ["js", "py"],
    re: /\b(?:value|lamports)\s*[:=]\s*\w*[Bb]alance\w*\b(?:\s*-\s*\w+)?|['"]value['"]\s*:\s*\w*balance\w*/g,
    tags: ["sweep"]
  },
  {
    id: "unlimited-approval",
    langs: ["js", "py"],
    re: /approve\(\s*['"`]0x[0-9a-fA-F]{40}['"`]\s*,\s*(?:ethers\.)?(?:constants\.)?(?:MaxUint256|maxUint256|MAX_UINT256|2\s*\*\*\s*256\s*-\s*1|2n\s*\*\*\s*256n\s*-\s*1n)/g,
    tags: [],
    accept: isUnknownRecipient,
    alone: {
      severity: "medium",
      category: "wallet",
      title: "Grants an unlimited token approval to a hard-coded address",
      detail: "It lets a fixed address spend all of a token. Fine for a known DEX router, catastrophic if the address belongs to the author.",
      advice: "Look the address up on a block explorer before running this with a funded wallet."
    }
  }
];

// packages/core/src/analyzers/scam-text.ts
var REMIX = /remix(?:\.ethereum\.org|\s+ide)?\b/i;
var FUND = /\b(?:fund|deposit|send|transfer)\b[^\n]{0,80}?\b(?:ETH|BNB|ether|MATIC|POL|AVAX|ARB)\b/i;
var START = /\bstart\s*\(\s*\)|\bclick\s+(?:on\s+)?["'“]?start|\b(?:call|press|hit)\s+["'“]?start\b|\bstart\s+(?:the\s+)?bot\b/i;
var TEXT_RULES = [
  {
    id: "seed-phrase-request",
    re: /\b(?:enter|paste|input|provide|type|submit|share|import|send)\s+(?:in\s+)?(?:your\s+)?(?:12|24|twelve|twenty[- ]four)?[- ]?(?:word\s+)?(?:seed\s*phrase|recovery\s*phrase|secret\s+recovery\s+phrase|mnemonic(?:\s+phrase)?)/gi,
    severity: "medium",
    title: "Asks for your seed phrase",
    detail: "A seed phrase controls every account in a wallet, forever. No legitimate bot needs it; use a fresh wallet with only the funds you're willing to lose if you ever must."
  },
  {
    id: "activation-fee",
    re: /\b(?:send|pay|deposit|transfer)\b[^.\n]{0,50}\b(?:to\s+activate|activation\s+fee|to\s+unlock|unlock\s+fee|license\s+fee|whitelist\s+fee)/gi,
    severity: "high",
    title: "Asks you to pay or deposit to 'activate' the bot",
    detail: "Activation or unlock deposits are the payout of the scam itself."
  },
  {
    id: "disable-antivirus",
    re: /\b(?:disable|turn\s+off|deactivate|pause)\s+(?:your\s+)?(?:anti-?virus|windows\s+defender|defender|real[- ]time\s+protection|smartscreen)|\badd\s+(?:an?\s+)?(?:exclusion|exception)\s+(?:in|to|for)\s+(?:windows\s+)?defender/gi,
    severity: "high",
    title: "Tells you to disable your antivirus",
    detail: "Real software does not need Defender turned off. Malware authors ask because otherwise it gets caught."
  },
  {
    id: "profit-promise",
    re: /\b(?:guaranteed|risk[- ]free)\s+(?:profits?|returns?|income|gains)|\b\d{1,4}(?:\.\d+)?\s*%\s*(?:daily|per\s+day|a\s+day|every\s+day)\b|\bpassive\s+income\b|\bmake\s+\$\s?\d[\d,]*\s*(?:a|per)\s+day\b/gi,
    severity: "medium",
    title: "Promises guaranteed or daily profits",
    detail: "No trading strategy guarantees returns. Profit promises are the bait in most bot scams."
  },
  {
    id: "binary-download",
    re: /https?:\/\/(?:mega\.nz|(?:www\.)?mediafire\.com|gofile\.io|pixeldrain\.com|anonfiles|catbox\.moe|transfer\.sh)[^\s)'"<>]*|https?:\/\/(?!(?:[\w-]+\.)*(?:aka\.ms|microsoft\.com|python\.org|nodejs\.org|git-scm\.com|visualstudio\.com|nvidia\.com|intel\.com|oracle\.com|docker\.com|rust-lang\.org|golang\.org|go\.dev|mozilla\.org|google\.com)\/)[^\s)'"<>]+\.(?:exe|scr|msi|rar|7z)\b/gi,
    severity: "medium",
    title: "Distributes the bot as a download from a file host",
    detail: "The bot is offered as an executable or archive from a file host instead of source you can read. That is how many trading-bot infostealers spread."
  }
];
function docDepth(path) {
  return path.replace(/^(?:sdist|wheel)\//, "").split("/").length - 1;
}
function isUserFacingDoc(path) {
  if (langOf(path) !== "text" && !/(^|\/)readme/i.test(path)) return false;
  if (/(^|\/)(?:node_modules|vendor|third_party|tests?|docs?\/api)\//i.test(path)) return false;
  return /(^|\/)readme[^/]*$/i.test(path) ? docDepth(path) <= 1 : docDepth(path) === 0;
}
function scanScamText(files) {
  const findings = [];
  const docs = files.filter((f) => isUserFacingDoc(f.path));
  for (const file of docs.slice(0, 60)) {
    const lines = new LineIndex(file.text);
    for (const rule of TEXT_RULES) {
      const evidence = [];
      for (const m of file.text.matchAll(rule.re)) {
        evidence.push(lines.evidence(file.path, m.index, m[0].length));
        if (evidence.length >= 2) break;
      }
      if (evidence.length) {
        findings.push({ id: `text.${rule.id}`, severity: rule.severity, category: "scam-text", title: rule.title, detail: rule.detail, advice: rule.advice, evidence });
      }
    }
    const remix = REMIX.exec(file.text);
    const fund = FUND.exec(file.text);
    const start = START.exec(file.text);
    if (remix && fund && start) {
      findings.push({
        id: "text.remix-fund-start",
        severity: "critical",
        category: "scam-text",
        title: "Matches the 'deploy in Remix, fund it, press start' bot scam",
        detail: "The instructions have you deploy a contract yourself, send it ETH/BNB, then call start(). In this scam the contract forwards everything to the author. Wallet warnings never fire because you deploy it yourself.",
        advice: "Never fund a contract you cannot read line by line. Scan the contract source here first.",
        evidence: [remix, fund, start].map((m) => lines.evidence(file.path, m.index, m[0].length))
      });
    }
  }
  return findings;
}

// packages/core/src/intel/brands.ts
var BRANDS = [
  { key: "polymarket", label: "Polymarket", pattern: /poly[-_.]?market/i, npmScopes: ["@polymarket"], githubOrgs: ["polymarket"], emailDomains: ["polymarket.com"] },
  { key: "kalshi", label: "Kalshi", pattern: /kalshi/i, npmScopes: ["@kalshi"], githubOrgs: ["kalshi"], emailDomains: ["kalshi.com"] },
  { key: "hyperliquid", label: "Hyperliquid", pattern: /hyper[-_.]?liquid/i, npmScopes: ["@hyperliquid"], githubOrgs: ["hyperliquid-dex"], emailDomains: ["hyperliquid.xyz"] },
  { key: "uniswap", label: "Uniswap", pattern: /uniswap/i, npmScopes: ["@uniswap"], githubOrgs: ["uniswap"], emailDomains: ["uniswap.org"] },
  { key: "metamask", label: "MetaMask", pattern: /meta[-_.]?mask/i, npmScopes: ["@metamask"], githubOrgs: ["metamask"], emailDomains: ["consensys.net", "metamask.io"] },
  { key: "phantom", label: "Phantom", pattern: /phantom[-_.]?(wallet|app|sdk|connect)/i, npmScopes: ["@phantom"], githubOrgs: ["phantom"], emailDomains: ["phantom.app"] },
  { key: "binance", label: "Binance", pattern: /binance/i, npmScopes: ["@binance"], githubOrgs: ["binance"], emailDomains: ["binance.com"] },
  { key: "coinbase", label: "Coinbase", pattern: /coinbase/i, npmScopes: ["@coinbase"], githubOrgs: ["coinbase"], emailDomains: ["coinbase.com"] },
  { key: "jupiter", label: "Jupiter", pattern: /jupiter[-_.]?(ag|swap|aggregator|exchange)|jup[-_.]?ag/i, npmScopes: ["@jup-ag"], githubOrgs: ["jup-ag"], emailDomains: ["jup.ag"] },
  { key: "raydium", label: "Raydium", pattern: /raydium/i, npmScopes: ["@raydium-io"], githubOrgs: ["raydium-io"], emailDomains: ["raydium.io"] },
  { key: "pumpfun", label: "pump.fun", pattern: /pump[-_.]?fun/i, npmScopes: ["@pump-fun"], githubOrgs: ["pump-fun"], emailDomains: ["pump.fun"] },
  { key: "axiom", label: "Axiom", pattern: /axiom[-_.]?trade/i, npmScopes: [], githubOrgs: [], emailDomains: ["axiom.trade"] },
  { key: "tg-bots", label: "a well-known trading bot", pattern: /bonk[-_.]?bot|banana[-_.]?gun|maestro[-_.]?bot|trojan[-_.]?(bot|sol)|kreo[-_.]?poly|polygun|polycop/i, npmScopes: [], githubOrgs: [], emailDomains: [] },
  { key: "anthropic", label: "Claude / Anthropic", pattern: /claude|anthropic/i, npmScopes: ["@anthropic-ai"], githubOrgs: ["anthropics"], emailDomains: ["anthropic.com"] }
];
function matchBrands(name) {
  return BRANDS.filter((b) => b.pattern.test(name));
}
function githubOrgOf(url) {
  const m = url?.match(/github\.com[/:]([^/]+)\//i);
  return m?.[1]?.toLowerCase();
}
function isOfficialPublisher(brand, hints) {
  if (hints.scope && brand.npmScopes.includes(hints.scope.toLowerCase())) return true;
  const orgs = [githubOrgOf(hints.repositoryUrl), githubOrgOf(hints.homepage)].filter(Boolean);
  if (orgs.some((o) => brand.githubOrgs.includes(o))) return true;
  return (hints.emails ?? []).some((e) => brand.emailDomains.some((d) => e.toLowerCase().endsWith(`@${d}`)));
}

// packages/core/src/intel/deps.ts
var import_semver2 = __toESM(require_semver2(), 1);

// packages/core/src/registry/npm.ts
var import_semver = __toESM(require_semver2(), 1);
var REGISTRY = "https://registry.npmjs.org";
function encodeNpmName(name) {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}
function npmScope(name) {
  return name.startsWith("@") ? name.split("/")[0] : void 0;
}
function repoUrlOf(repo) {
  const raw = typeof repo === "string" ? repo : repo?.url;
  if (!raw) return void 0;
  return raw.replace(/^git\+/, "").replace(/^git:\/\//, "https://").replace(/^ssh:\/\/git@/, "https://").replace(/^github:/, "https://github.com/").replace(/\.git$/, "");
}
async function getNpmPackument(name, timeoutMs = 1e4) {
  return fetchJson(`${REGISTRY}/${encodeNpmName(name)}`, { timeoutMs, maxBytes: 40 * 1024 * 1024 });
}
async function getNpmVersionList(name, timeoutMs = 1e4) {
  const doc = await fetchJson(`${REGISTRY}/${encodeNpmName(name)}`, {
    timeoutMs,
    headers: { accept: "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8" },
    maxBytes: 40 * 1024 * 1024
  });
  return doc ? Object.keys(doc.versions ?? {}) : null;
}
async function getNpmVersion(name, spec = "latest", timeoutMs = 8e3) {
  return fetchJson(`${REGISTRY}/${encodeNpmName(name)}/${encodeURIComponent(spec)}`, { timeoutMs });
}
function resolveNpmSpec(p, spec) {
  const tags = p["dist-tags"] ?? {};
  if (!spec || spec === "*" || spec === "") return tags.latest ?? null;
  if (tags[spec]) return tags[spec];
  if (p.versions[spec]) return spec;
  const versions = Object.keys(p.versions);
  try {
    if (tags.latest && import_semver.default.satisfies(tags.latest, spec)) return tags.latest;
    return import_semver.default.maxSatisfying(versions, spec);
  } catch {
    return null;
  }
}
function isDirectSpec(spec) {
  return !spec || /^[a-z][\w.-]*$/i.test(spec) || import_semver.default.valid(spec) !== null;
}
async function getNpmWeeklyDownloads(name, timeoutMs = 6e3) {
  const res = await fetchJson(
    `https://api.npmjs.org/downloads/point/last-week/${name}`,
    { timeoutMs }
  ).catch(() => null);
  return typeof res?.downloads === "number" ? res.downloads : null;
}

// packages/core/src/registry/pep440.ts
var RE = /^\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$/i;
function parsePep440(v) {
  const m = RE.exec(v);
  if (!m) return null;
  const preTag = m[3]?.toLowerCase();
  const preKind = preTag === void 0 ? void 0 : preTag.startsWith("a") ? 0 : preTag === "b" || preTag === "beta" ? 1 : 2;
  return {
    epoch: m[1] ? Number(m[1]) : 0,
    release: m[2].split(".").map(Number),
    pre: preKind === void 0 ? void 0 : [preKind, m[4] ? Number(m[4]) : 0],
    post: m[5] ? Number(m[5]) : m[6] ? m[7] ? Number(m[7]) : 0 : void 0,
    dev: m[8] ? m[9] ? Number(m[9]) : 0 : void 0,
    raw: v
  };
}
function isPrerelease(v) {
  return v.pre !== void 0 || v.dev !== void 0;
}
function cmpRelease(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}
function comparePep440(a, b) {
  if (a.epoch !== b.epoch) return a.epoch - b.epoch;
  const r = cmpRelease(a.release, b.release);
  if (r !== 0) return r;
  const preKey = (v) => v.pre ? v.pre[0] * 1e6 + v.pre[1] : v.dev !== void 0 && v.post === void 0 ? -1 : 9e9;
  const p = preKey(a) - preKey(b);
  if (p !== 0) return p;
  const post = (a.post ?? -1) - (b.post ?? -1);
  if (post !== 0) return post;
  return (a.dev ?? Infinity) - (b.dev ?? Infinity);
}
function matchOne(v, op, target) {
  if (op === "===") return v.raw === target;
  if (target.endsWith(".*") && (op === "==" || op === "!=")) {
    const prefix = parsePep440(target.slice(0, -2));
    if (!prefix) return false;
    const eq = prefix.release.every((n, i) => (v.release[i] ?? 0) === n) && v.epoch === prefix.epoch;
    return op === "==" ? eq : !eq;
  }
  const t = parsePep440(target);
  if (!t) return false;
  const c = comparePep440(v, t);
  switch (op) {
    case "==":
      return c === 0;
    case "!=":
      return c !== 0;
    case ">=":
      return c >= 0;
    case "<=":
      return c <= 0;
    case ">":
      return c > 0;
    case "<":
      return c < 0;
    case "~=": {
      if (c < 0 || t.release.length < 2) return false;
      const upper = t.release.slice(0, -1);
      return upper.every((n, i) => (v.release[i] ?? 0) === n);
    }
    default:
      return false;
  }
}
function satisfiesPep440(version, specifier) {
  const v = parsePep440(version);
  if (!v) return false;
  const parts = specifier.split(",").map((s) => s.trim()).filter(Boolean);
  return parts.every((part) => {
    const m = /^(===|==|!=|~=|>=|<=|>|<)\s*(.+)$/.exec(part);
    return m ? matchOne(v, m[1], m[2].trim()) : false;
  });
}
function maxSatisfyingPep440(versions, specifier) {
  const parsed = versions.map((raw) => parsePep440(raw)).filter((v) => v !== null);
  const ok = parsed.filter((v) => !specifier || satisfiesPep440(v.raw, specifier));
  const finals = ok.filter((v) => !isPrerelease(v));
  const pool = finals.length ? finals : ok;
  pool.sort(comparePep440);
  return pool.at(-1)?.raw ?? null;
}

// packages/core/data/popular-npm.json
var popular_npm_default = { source: "npm-high-impact", generated: "2026-10-15", names: ["semver", "minimatch", "debug", "ansi-styles", "brace-expansion", "strip-ansi", "ansi-regex", "ms", "supports-color", "chalk", "commander", "lru-cache", "string-width", "wrap-ansi", "tslib", "picomatch", "emoji-regex", "glob", "type-fest", "color-name", "eslint-visitor-keys", "color-convert", "ajv", "minipass", "source-map", "balanced-match", "readable-stream", "which", "glob-parent", "escape-string-regexp", "has-flag", "find-up", "locate-path", "json-schema-traverse", "p-limit", "yallist", "safe-buffer", "uuid", "p-locate", "undici-types", "ignore", "iconv-lite", "signal-exit", "esbuild", "is-fullwidth-code-point", "js-yaml", "entities", "globals", "postcss", "isexe", "isarray", "path-key", "string_decoder", "argparse", "ws", "mime-db", "resolve", "agent-base", "@esbuild/linux-x64", "yargs-parser", "mime-types", "acorn", "estraverse", "cross-spawn", "react-is", "picocolors", "fs-extra", "hasown", "nanoid", "yargs", "resolve-from", "shebang-command", "pretty-format", "json5", "https-proxy-agent", "path-to-regexp", "path-exists", "punycode", "js-tokens", "cliui", "shebang-regex", "@babel/types", "chokidar", "strip-json-comments", "inherits", "webidl-conversions", "get-stream", "eslint-scope", "cookie", "@babel/parser", "qs", "is-number", "whatwg-url", "@types/estree", "tr46", "convert-source-map", "is-glob", "braces", "fast-deep-equal", "form-data", "lodash", "@babel/helper-validator-identifier", "electron-to-chromium", "fill-range", "function-bind", "readdirp", "escalade", "graceful-fs", "negotiator", "is-stream", "camelcase", "@babel/runtime", "yocto-queue", "to-regex-range", "node-fetch", "micromatch", "node-releases", "get-intrinsic", "universalify", "path-scurry", "jsesc", "browserslist", "es-errors", "statuses", "@radix-ui/react-primitive", "magic-string", "rimraf", "is-extglob", "@jridgewell/trace-mapping", "@jridgewell/resolve-uri", "http-errors", "onetime", "has-symbols", "es-define-property", "gopd", "util-deprecate", "object-assign", "jiti", "yaml", "dotenv", "@babel/generator", "@babel/template", "imurmurhash", "postcss-selector-parser", "fast-glob", "update-browserslist-db", "@types/node", "@babel/compat-data", "eventemitter3", "callsites", "http-proxy-agent", "detect-libc", "espree", "execa", "@babel/core", "@babel/helpers", "concat-map", "source-map-js", "tinyglobby", "call-bind-apply-helpers", "flat-cache", "fdir", "pify", "@jest/types", "normalize-path", "is-core-module", "eslint", "minimist", "estree-walker", "file-entry-cache", "object-inspect", "buffer", "uri-js", "import-fresh", "@babel/helper-module-transforms", "optionator", "flatted", "math-intrinsics", "safer-buffer", "y18n", "@babel/helper-module-imports", "mkdirp", "dunder-proto", "path-parse", "fastq", "levn", "@babel/helper-compilation-targets", "@babel/helper-string-parser", "keyv", "get-proto", "csstype", "npm-run-path", "fast-json-stable-stringify", "reusify", "@babel/helper-plugin-utils", "kind-of", "mime", "caniuse-lite", "lines-and-columns", "fast-levenshtein", "supports-preserve-symlinks-flag", "make-dir", "slash", "prelude-ls", "typescript", "strip-bom", "parent-module", "esutils", "ci-info", "@smithy/util-utf8", "type-check", "mimic-fn", "@babel/helper-validator-option", "@types/json-schema", "@rolldown/pluginutils", "side-channel-list", "json-buffer", "raw-body", "has-tostringtag", "wrappy", "diff", "jackspeak", "baseline-browser-mapping", "deep-is", "foreground-child", "@eslint/js", "anymatch", "natural-compare", "esquery", "@eslint-community/regexpp", "es-set-tostringtag", "acorn-jsx", "parse5", "finalhandler", "parse-json", "depd", "axios", "run-parallel", "source-map-support", "esrecurse", "call-bound", "content-disposition", "human-signals", "ts-api-utils", "ansi-escapes", "jest-util", "send", "@opentelemetry/core", "type-is", "encodeurl", "once", "cosmiconfig", "lodash.merge", "json-stable-stringify-without-jsonify", "open", "prettier", "@eslint/eslintrc", "is-arrayish", "@jridgewell/sourcemap-codec", "gensync", "word-wrap", "express", "arg", "jsonfile", "schema-utils", "@smithy/is-array-buffer", "@typescript-eslint/types", "chownr", "delayed-stream", "@smithy/util-buffer-from", "asynckit", "tapable", "enhanced-resolve", "aria-query", "indent-string", "bytes", "binary-extensions", "ini", "@radix-ui/react-context", "doctrine", "queue-microtask", "accepts", "merge2", "get-caller-file", "@humanwhocodes/retry", "@jridgewell/gen-mapping", "@typescript-eslint/typescript-estree", "jest-worker", "proxy-from-env", "clsx", "side-channel-map", "@typescript-eslint/visitor-keys", "fresh", "restore-cursor", "on-finished", "is-plain-obj", "ipaddr.js", "pathe", "@jest/schemas", "base64-js", "@smithy/types", "require-directory", "tough-cookie", "is-binary-path", "body-parser", "postcss-value-parser", "media-typer", "setprototypeof", "side-channel-weakmap", "@typescript-eslint/tsconfig-utils", "@isaacs/cliui", "@rollup/rollup-linux-x64-gnu", "is-wsl", "retry", "@aws-sdk/types", "@types/react-dom", "combined-stream", "es-object-atoms", "@eslint/core", "whatwg-mimetype", "domutils", "@rollup/rollup-linux-x64-musl", "core-util-is", "@typescript-eslint/scope-manager", "esprima", "loose-envify", "cookie-signature", "follow-redirects", "cli-cursor", "strip-final-newline", "@typescript-eslint/project-service", "eastasianwidth", "json-parse-even-better-errors", "sprintf-js", "path-type", "content-type", "es-module-lexer", "@nodelib/fs.scandir", "write-file-atomic", "@eslint/plugin-kit", "ieee754", "prop-types", "require-from-string", "dom-serializer", "call-bind", "@eslint/config-array", "has-property-descriptors", "@nodelib/fs.stat", "merge-descriptors", "slice-ansi", "rxjs", "p-map", "toidentifier", "globby", "domhandler", "async", "@babel/helper-globals", "pirates", "@opentelemetry/semantic-conventions", "@typescript-eslint/utils", "date-fns", "is-docker", "tar", "which-typed-array", "ajv-formats", "@opentelemetry/api-logs", "@opentelemetry/resources", "side-channel", "cjs-module-lexer", "range-parser", "@humanfs/node", "define-data-property", "node-addon-api", "pako", "lilconfig", "fast-uri", "ip-address", "fs.realpath", "@img/sharp-libvips-linuxmusl-x64", "cssesc", "@opentelemetry/instrumentation", "domelementtype", "hosted-git-info", "@eslint/object-schema", "etag", "@eslint/config-helpers", "package-json-from-dist", "@humanfs/core", "htmlparser2", "jest-message-util", "for-each", "pkg-dir", "unpipe", "buffer-from", "es-abstract", "is-unicode-supported", "@types/yargs", "is-callable", "fast-xml-parser", "istanbul-lib-instrument", "escape-html", "is-regex", "dom-accessibility-api", "css-tree", "error-ex", "ee-first", "@types/unist", "log-symbols", "path-is-absolute", "end-of-stream", "@vitest/utils", "object.assign", "object-keys", "tinyexec", "scheduler", "p-try", "process-nextick-args", "vary", "@babel/traverse", "@pkgjs/parseargs", "@types/babel__generator", "kleur", "zod", "merge-stream", "available-typed-arrays", "mute-stream", "is-typed-array", "safe-regex-test", "tsconfig-paths", "minizlib", "tar-stream", "@floating-ui/core", "jose", "deepmerge", "get-tsconfig", "set-function-length", "@vitest/spy", "css-select", "@types/babel__core", "forwarded", "react", "@typescript-eslint/parser", "ajv-keywords", "define-properties", "is-generator-function", "regexp.prototype.flags", "acorn-walk", "pump", "data-uri-to-buffer", "object-hash", "jsdom", "nopt", "@babel/plugin-syntax-jsx", "@floating-ui/dom", "tiny-invariant", "strip-indent", "d3-array", "chai", "@babel/code-frame", "@typescript-eslint/eslint-plugin", "proxy-addr", "parseurl", "@floating-ui/utils", "ora", "html-encoding-sniffer", "pnpm", "whatwg-encoding", "events", "@typescript-eslint/type-utils", "env-paths", "internal-slot", "string.prototype.trimend", "extend", "resolve-pkg-maps", "istanbul-lib-coverage", "react-dom", "is-number-object", "@radix-ui/primitive", "is-plain-object", "string.prototype.trimstart", "@babel/plugin-syntax-typescript", "jest-diff", "define-lazy-prop", "globalthis", "which-boxed-primitive", "@vitest/expect", "sax", "@floating-ui/react-dom", "@vitest/pretty-format", "internmap", "@radix-ui/react-compose-refs", "is-symbol", "@eslint-community/eslint-utils", "bl", "serve-static", "get-symbol-description", "is-shared-array-buffer", "functions-have-names", "array-buffer-byte-length", "socks-proxy-agent", "extend-shallow", "@radix-ui/react-use-layout-effect", "function.prototype.name", "is-bigint", "is-string", "protobufjs", "tmp", "is-date-object", "lightningcss-linux-x64-musl", "proc-log", "long", "@opentelemetry/sdk-trace-base", "nth-check", "d3-path", "@types/babel__template", "jest-regex-util", "@radix-ui/react-use-controllable-state", "jest-mock", "socks", "lightningcss", "assertion-error", "es-to-primitive", "tinyrainbow", "possible-typed-array-names", "figures", "xml-name-validator", "any-promise", "d3-shape", "terser", "std-env", "is-array-buffer", "safe-array-concat", "@aws-sdk/token-providers", "data-urls", "d3-interpolate", "@radix-ui/react-dismissable-layer", "set-function-name", "css-what", "typed-array-length", "typed-array-byte-offset", "thenify", "mz", "react-remove-scroll", "@radix-ui/react-id", "is-weakset", "is-boolean-object", "@alloc/quick-lru", "html-escaper", "has-bigints", "@aws-sdk/credential-provider-node", "lightningcss-linux-x64-gnu", "@radix-ui/react-presence", "w3c-xmlserializer", "istanbul-reports", "@babel/helper-annotate-as-pure", "typed-array-buffer", "@nodelib/fs.walk", "sharp", "arraybuffer.prototype.slice", "d3-format", "has-proto", "d3-timer", "lodash.isplainobject", "@aws-sdk/util-endpoints", "@radix-ui/react-use-callback-ref", "d3-time-format", "is-weakref", "autoprefixer", "istanbul-lib-report", "postcss-load-config", "strnum", "core-js", "@vitest/snapshot", "@aws-sdk/credential-provider-env", "define-property", "@sinonjs/fake-timers", "@aws-sdk/credential-provider-web-identity", "clone", "normalize-package-data", "d3-color", "d3-time", "colorette", "is-negative-zero", "unbox-primitive", "data-view-byte-length", "data-view-buffer", "regenerator-runtime", "is-set", "saxes", "decimal.js", "@aws-sdk/core", "@radix-ui/react-portal", "d3-scale", "dequal", "which-collection", "cli-width", "@radix-ui/react-use-escape-keydown", "@swc/helpers", "data-view-byte-offset", "@aws-sdk/util-user-agent-node", "is-map", "is-path-inside", "xtend", "is-finalizationregistry", "import-in-the-middle", "xmlbuilder", "@sinclair/typebox", "is-async-function", "tsx", "d3-ease", "jwa", "@aws-sdk/middleware-user-agent", "@types/express-serve-static-core", "thenify-all", "@jridgewell/remapping", "@vitest/runner", "decamelize", "clean-stack", "abbrev", "@aws-sdk/middleware-logger", "type-detect", "@radix-ui/react-collection", "@radix-ui/react-focus-scope", "loader-utils", "mimic-response", "string.prototype.trim", "fraction.js", "ast-types", "which-builtin-type", "array-includes", "@bcoe/v8-coverage", "expect", "@types/d3-shape", "@smithy/protocol-http", "cli-spinners", "@types/d3-time", "@types/d3-color", "@radix-ui/react-focus-guards", "sucrase", "typed-array-byte-length", "@radix-ui/react-popper", "aria-hidden", "escodegen", "@types/d3-array", "bn.js", "split2", "http-cache-semantics", "utils-merge", "buffer-crc32", "boolbase", "@smithy/fetch-http-handler", "@types/d3-path", "@ungap/structured-clone", "@radix-ui/react-direction", "react-remove-scroll-bar", "@types/send", "mdn-data", "cors", "@types/express", "is-weakmap", "reflect.getprototypeof", "jest-haste-map", "eslint-config-prettier", "postcss-import", "neo-async", "array-union", "ssri", "@types/d3-interpolate", "@aws-sdk/middleware-host-header", "@radix-ui/react-visually-hidden", "@babel/helper-replace-supers", "@radix-ui/react-arrow", "stop-iteration-iterator", "@aws-sdk/credential-provider-process", "istanbul-lib-source-maps", "dedent", "is-data-view", "@smithy/signature-v4", "redent", "@aws-sdk/credential-provider-http", "is-promise", "object.values", "@istanbuljs/schema", "@sindresorhus/is", "own-keys", "@jest/fake-timers", "safe-push-apply", "cssstyle", "destroy", "@jest/transform", "react-transition-group", "@babel/helper-member-expression-to-functions", "ts-interface-checker", "dom-helpers", "@opentelemetry/api", "@img/sharp-linux-x64", "isobject", "array.prototype.flatmap", "@types/ws", "es-shim-unscopables", "vitest", "array.prototype.flat", "@babel/plugin-syntax-import-attributes", "gcp-metadata", "@emnapi/runtime", "@types/chai", "@types/prop-types", "@types/d3-ease", "@babel/helper-create-class-features-plugin", "@radix-ui/react-roving-focus", "@jest/environment", "jest-matcher-utils", "symbol-tree", "detect-node-es", "test-exclude", "dlv", "@vitest/mocker", "@smithy/property-provider", "xmlchars", "webpack-sources", "@smithy/util-middleware", "shell-quote", "smart-buffer", "set-proto", "graphemer", "@aws-sdk/region-config-resolver", "@aws-sdk/util-user-agent-browser", "gaxios", "is-extendable", "@radix-ui/react-dialog", "vite", "get-nonce", "is-potential-custom-element-name", "@types/d3-timer", "@smithy/querystring-builder", "inflight", "@radix-ui/react-use-size", "leven", "@tailwindcss/oxide-linux-x64-musl", "@aws-sdk/middleware-recursion-detection", "read-cache", "@types/ms", "@aws-sdk/xml-builder", "google-auth-library", "why-is-node-running", "aggregate-error", "setimmediate", "read-pkg", "@smithy/smithy-client", "react-hook-form", "methods", "@sinonjs/commons", "object.entries", "babel-jest", "@types/serve-static", "is-interactive", "event-target-shim", "jest-get-type", "postcss-js", "@rollup/pluginutils", "tldts-core", "class-variance-authority", "@napi-rs/wasm-runtime", "@openai/codex", "@jest/console", "@radix-ui/react-use-previous", "pure-rand", "object.fromentries", "babel-plugin-istanbul", "dir-glob", "siginfo", "jest-validate", "@smithy/middleware-endpoint", "babel-plugin-polyfill-corejs3", "@types/istanbul-lib-coverage", "babel-plugin-jest-hoist", "async-function", "array-flatten", "didyoumean", "tinybench", "get-east-asian-width", "@smithy/shared-ini-file-loader", "dayjs", "recharts", "@jest/test-result", "@radix-ui/rect", "@octokit/types", "@babel/plugin-transform-react-jsx-source", "@tootallnate/once", "@protobufjs/utf8", "@protobufjs/codegen", "rollup", "@radix-ui/number", "@smithy/core", "@types/qs", "jest-environment-node", "@protobufjs/inquire", "@babel/plugin-transform-modules-commonjs", "ansi-colors", "jest-resolve", "@smithy/util-base64", "cssom", "@smithy/credential-provider-imds", "ecdsa-sig-formatter", "eslint-import-resolver-node", "camelcase-css", "immer", "victory-vendor", "@smithy/middleware-serde", "@tailwindcss/node", "@types/yargs-parser", "@radix-ui/react-label", "@babel/helper-optimise-call-expression", "process", "@aws-sdk/nested-clients", "@smithy/url-parser", "fast-equals", "@noble/hashes", "jest-snapshot", "@tailwindcss/oxide", "@smithy/middleware-stack", "cli-truncate", "eslint-plugin-import", "@testing-library/dom", "webpack", "@csstools/css-tokenizer", "@smithy/util-retry", "serialize-javascript", "@smithy/service-error-classification", "@types/react", "@radix-ui/react-dropdown-menu", "jest-docblock", "sisteransi", "@aws-sdk/credential-provider-ini", "postcss-nested", "@smithy/querystring-parser", "lie", "@smithy/util-stream", "@colors/colors", "requires-port", "string-length", "web-streams-polyfill", "@radix-ui/react-tooltip", "@smithy/node-config-provider", "@octokit/openapi-types", "diff-sequences", "unist-util-visit", "@smithy/util-uri-escape", "@types/istanbul-reports", "tar-fs", "expect-type", "is-buffer", "@testing-library/jest-dom", "@types/deep-eql", "terser-webpack-plugin", "unist-util-visit-parents", "@tanstack/query-core", "file-type", "watchpack", "@radix-ui/react-separator", "synckit", "babel-preset-jest", "@smithy/middleware-retry", "@smithy/util-hex-encoding", "@radix-ui/react-menu", "eslint-plugin-react", "prompts", "@types/body-parser", "find-cache-dir", "unist-util-is", "make-fetch-happen", "chardet", "jest-watcher", "core-js-compat", "jws", "stack-utils", "is-obj", "@types/range-parser", "@radix-ui/react-select", "jest-runtime", "@smithy/util-endpoints", "inquirer", "rfdc", "unist-util-stringify-position", "import-local", "@radix-ui/react-collapsible", "through2", "@smithy/util-defaults-mode-node", "@radix-ui/react-popover", "regjsparser", "node-gyp", "string.prototype.matchall", "unplugin", "micromark-util-symbol", "color", "decimal.js-light", "nwsapi", "abort-controller", "spdx-expression-parse", "@radix-ui/react-tabs", "@protobufjs/eventemitter", "jest", "@tanstack/react-query", "jsonwebtoken", "@jest/reporters", "@protobufjs/fetch", "tailwindcss", "unique-filename", "make-error", "color-string", "@hookform/resolvers", "glob-to-regexp", "bluebird", "@adobe/css-tools", "@tailwindcss/oxide-linux-x64-gnu", "ts-node", "@smithy/hash-node", "is-descriptor", "@inquirer/type", "psl", "typescript-eslint", "wordwrap", "jest-cli", "@csstools/css-calc", "resolve-cwd", "@types/json5", "@csstools/css-parser-algorithms", "@jest/globals", "@protobufjs/aspromise", "@img/sharp-linuxmusl-x64", "@radix-ui/react-progress", "@jest/expect-utils", "fflate", "get-package-type", "@types/hast", "jest-leak-detector", "@types/istanbul-lib-report", "@babel/plugin-transform-classes", "@types/mdast", "pathval", "safe-stable-stringify", "node-int64", "@radix-ui/react-toggle", "@babel/helper-define-polyfill-provider", "loupe", "char-regex", "@babel/plugin-transform-block-scoping", "jest-runner", "eslint-module-utils", "decompress-response", "uglify-js", "@smithy/util-defaults-mode-browser", "@radix-ui/react-avatar", "jest-circus", "micromark-util-character", "google-logging-utils", "regexpu-core", "lz-string", "min-indent", "@babel/plugin-syntax-numeric-separator", "@babel/plugin-syntax-optional-catch-binding", "fb-watchman", "bser", "@babel/plugin-transform-spread", "deep-eql", "@babel/plugin-syntax-top-level-await", "@babel/plugin-syntax-nullish-coalescing-operator", "zod-to-json-schema", "progress", "@smithy/util-body-length-browser", "@babel/plugin-transform-parameters", "@jest/source-map", "immediate", "@aws-sdk/client-sso", "@babel/plugin-syntax-object-rest-spread", "normalize-url", "@smithy/config-resolver", "@babel/plugin-syntax-logical-assignment-operators", "@protobufjs/pool", "jest-changed-files", "@babel/plugin-syntax-json-strings", "@csstools/color-helpers", "@types/lodash", "webpack-virtual-modules", "jest-resolve-dependencies", "through", "util", "micromark-util-types", "cacache", "@types/stack-utils", "@emnapi/wasi-threads", "axobject-query", "@pkgr/core", "@radix-ui/react-scroll-area", "arrify", "@babel/plugin-transform-computed-properties", "array.prototype.findlastindex", "@opentelemetry/sdk-metrics", "@babel/plugin-transform-for-of", "@emnapi/core", "@babel/plugin-transform-async-to-generator", "@babel/plugin-syntax-class-properties", "defaults", "jsx-ast-utils", "yauzl", "jsonc-parser", "detect-newline", "@aws-crypto/sha256-js", "@types/http-errors", "require-in-the-middle", "@webassemblyjs/helper-wasm-bytecode", "@types/babel__traverse", "@babel/plugin-transform-literals", "@npmcli/fs", "@protobufjs/path", "check-error", "pg-types", "v8-to-istanbul", "babel-plugin-polyfill-corejs2", "@babel/plugin-transform-regenerator", "@testing-library/react", "@types/debug", "url-parse", "@aws-sdk/credential-provider-sso", "eventsource-parser", "bignumber.js", "emittery", "es-iterator-helpers", "wcwidth", "character-entities", "@babel/plugin-syntax-async-generators", "co", "express-rate-limit", "@babel/plugin-syntax-optional-chaining", "css.escape", "@babel/plugin-transform-destructuring", "@types/eslint", "@webassemblyjs/leb128", "character-entities-legacy", "@csstools/css-color-parser", "@webassemblyjs/ast", "querystringify", "vfile-message", "node-domexception", "@protobufjs/base64", "pkg-types", "minipass-collect", "tmpl", "lodash.once", "confbox", "@vitejs/plugin-react", "dompurify", "@babel/plugin-transform-template-literals", "regenerate-unicode-properties", "@webassemblyjs/wasm-opt", "@radix-ui/react-radio-group", "tinyspy", "vfile", "exponential-backoff", "walker", "@types/aria-query", "listr2", "@smithy/util-config-provider", "@webassemblyjs/helper-wasm-section", "object.groupby", "spdx-license-ids", "ufo", "@webassemblyjs/floating-point-hex-parser", "@smithy/middleware-content-length", "graphql", "loader-runner", "babel-plugin-polyfill-regenerator", "@babel/plugin-transform-function-name", "@types/jest", "@babel/plugin-transform-sticky-regex", "quick-lru", "yn", "@grpc/proto-loader", "unicode-match-property-value-ecmascript", "@babel/plugin-transform-arrow-functions", "immutable", "@babel/plugin-transform-shorthand-properties", "@radix-ui/react-alert-dialog", "micromark", "on-headers", "lodash.isstring", "router", "postgres-date", "p-retry", "array.prototype.tosorted", "@inquirer/core", "@types/uuid", "@grpc/grpc-js", "minipass-flush", "spdx-exceptions", "@webassemblyjs/utf8", "unicorn-magic", "@humanwhocodes/module-importer", "@inquirer/figures", "@smithy/util-body-length-node", "mdast-util-to-string", "@babel/helper-remap-async-to-generator", "jszip", "text-table", "eslint-plugin-react-refresh", "log-update", "stylis", "@webassemblyjs/wast-printer", "babel-preset-current-node-syntax", "@webassemblyjs/helper-api-error", "eslint-plugin-prettier", "string.prototype.repeat", "@webassemblyjs/wasm-gen", "@types/pg", "lodash.camelcase", "@jridgewell/source-map", "@babel/helper-wrap-function", "micromark-factory-space", "@webassemblyjs/ieee754", "@babel/plugin-transform-block-scoped-functions", "formdata-polyfill", "@babel/plugin-transform-member-expression-literals", "@babel/plugin-syntax-import-meta", "unique-slug", "@babel/plugin-syntax-private-property-in-object", "set-blocking", "fast-diff", "concat-stream", "lodash.includes", "jest-config", "minimalistic-assert", "@babel/plugin-syntax-import-assertions", "lodash.isinteger", "deep-extend", "@webassemblyjs/wasm-edit", "read-pkg-up", "@babel/plugin-transform-named-capturing-groups-regex", "he", "err-code", "asap", "bowser", "property-information", "cmdk", "iterator.prototype", "lodash.isboolean", "b4a", "@babel/plugin-transform-private-methods", "@istanbuljs/load-nyc-config", "@babel/plugin-transform-unicode-regex", "@babel/plugin-transform-nullish-coalescing-operator", "cac", "@babel/plugin-transform-optional-chaining", "set-cookie-parser", "@webassemblyjs/wasm-parser", "@babel/plugin-syntax-class-static-block", "@babel/helper-create-regexp-features-plugin", "is-inside-container", "run-async", "dot-prop", "@webassemblyjs/helper-buffer", "@babel/plugin-transform-dotall-regex", "meow", "makeerror", "is-generator-fn", "randombytes", "@babel/helper-skip-transparent-expression-wrappers", "process-warning", "array.prototype.findlast", "v8-compile-cache-lib", "lower-case", "@tsconfig/node12", "encoding", "@radix-ui/react-hover-card", "lodash.debounce", "minipass-sized", "fetch-blob", "jest-each", "@ampproject/remapping", "archiver-utils", "micromark-util-sanitize-uri", "@babel/plugin-transform-object-super", "@types/mime", "@babel/plugin-transform-duplicate-keys", "tunnel-agent", "@radix-ui/react-context-menu", "@radix-ui/react-navigation-menu", "run-applescript", "@babel/plugin-transform-modules-systemjs", "pend", "@swc/counter", "p-timeout", "validate-npm-package-license", "resolve.exports", "unified", "chrome-trace-event", "@modelcontextprotocol/sdk", "@tsconfig/node14", "@babel/plugin-transform-class-properties", "default-browser-id", "consola", "tree-kill", "minipass-pipeline", "@babel/plugin-transform-typescript", "@babel/plugin-transform-reserved-words", "handlebars", "rc", "pg-protocol", "@tsconfig/node10", "@babel/plugin-transform-property-literals", "napi-postinstall", "lodash-es", "commondir", "minipass-fetch", "pngjs", "@tsconfig/node16", "collect-v8-coverage", "path-browserify", "bare-events", "no-case", "xml2js", "bundle-name", "lodash.memoize", "fast-xml-builder", "use-sync-external-store", "got", "space-separated-tokens", "is-alphabetical", "spdx-correct", "is-decimal", "which-module", "embla-carousel", "lodash.isnumber", "json-stringify-safe", "micromark-util-chunked", "playwright-core", "@babel/plugin-transform-private-property-in-object", "@rtsao/scc", "@jridgewell/set-array", "wsl-utils", "unicode-canonical-property-names-ecmascript", "micromark-util-normalize-identifier", "compression", "@smithy/invalid-dependency", "@babel/plugin-transform-exponentiation-operator", "react-refresh", "zustand", "@aws-sdk/credential-provider-login", "@babel/preset-typescript", "dotenv-expand", "streamx", "@radix-ui/react-menubar", "@aws-sdk/middleware-sdk-s3", "unrs-resolver", "@xtuc/long", "@xtuc/ieee754", "node-gyp-build", "fast-fifo", "ccount", "is-arguments", "fs-constants", "jest-pnp-resolver", "@inquirer/confirm", "@webassemblyjs/helper-numbers", "@swc/core", "micromark-util-classify-character", "@babel/plugin-transform-unicode-escapes", "@swc/core-linux-x64-gnu", "zwitch", "compressible", "@emotion/memoize", "mdast-util-to-markdown", "embla-carousel-reactive-utils", "@opentelemetry/otlp-exporter-base", "@aws-crypto/sha256-browser", "parse-entities", "@babel/plugin-transform-numeric-separator", "memfs", "@babel/plugin-transform-new-target", "require-main-filename", "mdast-util-to-hast", "embla-carousel-react", "hono", "parse5-htmlparser2-tree-adapter", "moment", "micromark-factory-label", "unicode-property-aliases-ecmascript", "regjsgen", "@babel/plugin-transform-async-generator-functions", "mdast-util-from-markdown", "@humanwhocodes/object-schema", "default-browser", "unicode-match-property-ecmascript", "@babel/plugin-bugfix-v8-spread-parameters-in-optional-chaining", "playwright", "module-details-from-path", "acorn-import-attributes", "eslint-plugin-jsx-a11y", "micromark-util-subtokenize", "@jest/expect", "fast-safe-stringify", "micromark-factory-title", "normalize-range", "@hono/node-server", "html-entities", "cheerio", "@smithy/node-http-handler", "remark-parse", "@swc/types", "eventsource", "pino", "lowercase-keys", "micromark-core-commonmark", "node-forge", "@babel/plugin-bugfix-safari-id-destructuring-collision-in-function-expression", "damerau-levenshtein", "tinypool", "prettier-linter-helpers", "micromark-util-html-tag-name", "astral-regex", "mrmime", "micromark-util-combine-extensions", "@types/retry", "ast-types-flow", "p-cancelable", "ejs", "@testing-library/user-event", "react-resizable-panels", "micromark-util-encode", "trough", "language-tags", "@smithy/abort-controller", "micromark-util-resolve-all", "bail", "fs-minipass", "style-to-object", "@types/parse-json", "pg-connection-string", "input-otp", "@babel/plugin-transform-json-strings", "comma-separated-tokens", "cross-fetch", "fd-slicer", "postgres-interval", "@img/sharp-libvips-linux-x64", "longest-streak", "big.js", "crc-32", "micromark-util-decode-string", "map-obj", "json-schema", "@octokit/request", "validate-npm-package-name", "json-bigint", "@smithy/util-waiter", "micromark-factory-whitespace", "is-alphanumerical", "micromark-util-decode-numeric-character-reference", "reselect", "sonic-boom", "performance-now", "promise-retry", "p-finally", "@opentelemetry/otlp-transformer", "@babel/plugin-transform-object-rest-spread", "@opentelemetry/sdk-logs", "@humanwhocodes/config-array", "jsbn", "micromark-factory-destination", "pino-abstract-transport", "styled-jsx", "@types/semver", "@xmldom/xmldom", "@jest/test-sequencer", "devlop", "interpret", "mdast-util-phrasing", "@babel/plugin-proposal-private-property-in-object", "@types/tough-cookie", "redux", "svgo", "decode-named-character-reference", "character-reference-invalid", "duplexify", "tweetnacl", "typedarray", "client-only", "recast", "@opentelemetry/context-async-hooks", "widest-line", "hoist-non-react-statics", "@babel/plugin-bugfix-v8-static-class-fields-redefine-readonly", "language-subtag-registry", "inline-style-parser", "@babel/plugin-transform-logical-assignment-operators", "@jest/core", "gtoken", "@babel/plugin-transform-unicode-sets-regex", "mimic-function", "@smithy/eventstream-serde-node", "luxon", "supports-hyperlinks", "is-windows", "is-hexadecimal", "@types/eslint-scope", "is-typedarray", "@radix-ui/react-aspect-ratio", "hast-util-whitespace", "@oxc-project/types", "pino-std-serializers", "@humanfs/types", "@babel/plugin-transform-unicode-property-regex", "@smithy/eventstream-serde-config-resolver", "eslint-import-resolver-typescript", "memoize-one", "@tailwindcss/vite", "character-entities-html4", "@inquirer/ansi", "global-prefix", "dot-case", "pg-int8", "pluralize", "@octokit/request-error", "string-argv", "@next/env", "motion-utils", "@octokit/endpoint", "stringify-entities", "pg", "@types/graceful-fs", "image-size", "@radix-ui/react-toast", "unist-util-position", "camel-case", "@babel/plugin-transform-typeof-symbol", "husky", "exit", "@unrs/resolver-binding-linux-x64-gnu", "cacheable-request", "motion-dom", "flat", "@octokit/core", "cheerio-select", "@aws-sdk/client-s3", "@aws-sdk/util-locate-window", "rrweb-cssom", "ansis", "@babel/plugin-transform-modules-amd", "@graphql-tools/utils", "@smithy/eventstream-codec", "@babel/plugin-transform-modules-umd", "reflect-metadata", "@babel/highlight", "sirv", "component-emitter", "regenerate", "@babel/plugin-transform-react-jsx", "trim-lines", "@babel/plugin-syntax-unicode-sets-regex", "remark-rehype", "domexception", "@aws-crypto/util", "pg-pool", "obug", "enquirer", "simple-swizzle", "npm-package-arg", "universal-user-agent", "@unrs/resolver-binding-linux-x64-musl", "@aws-sdk/middleware-flexible-checksums", "@babel/preset-env", "faye-websocket", "promise", "lodash.uniq", "global-modules", "@babel/preset-modules", "nan", "@octokit/graphql", "proxy-agent", "@emotion/unitless", "rechoir", "abab", "@inquirer/external-editor", "responselike", "@aws-sdk/middleware-bucket-endpoint", "param-case", "@octokit/auth-token", "@protobufjs/float", "@smithy/eventstream-serde-universal", "create-require", "json-schema-typed", "thread-stream", "pretty-bytes", "@asamuzakjp/css-color", "@hapi/hoek", "next-themes", "environment", "@types/resolve", "ua-parser-js", "bare-stream", "asn1", "lodash.defaults", "@smithy/uuid", "crc32-stream", "at-least-node", "jake", "invariant", "csso", "@babel/plugin-bugfix-safari-class-field-initializer-scope", "bare-fs", "cookie-es", "filelist", "@babel/plugin-transform-optional-catch-binding", "@aws-sdk/util-arn-parser", "fsevents", "css-loader", "totalist", "is-bun-module", "hermes-estree", "pascal-case", "crypto-random-string", "hermes-parser", "zip-stream", "react-redux", "@octokit/plugin-paginate-rest", "acorn-globals", "@emotion/hash", "pg-cloudflare", "babel-plugin-macros", "pac-proxy-agent", "@babel/plugin-transform-class-static-block", "ret", "before-after-hook", "undici", "extsprintf", "deep-equal", "postcss-modules-scope", "pac-resolver", "zod-validation-error", "http-parser-js", "cli-boxes", "@aws-sdk/middleware-ssec", "degenerator", "archiver", "basic-ftp", "linkify-it", "@emotion/is-prop-valid", "emojis-list", "@babel/plugin-transform-export-namespace-from", "classnames", "bare-path", "cli-table3", "@polka/url", "extract-zip", "parse-ms", "websocket-driver", "shallow-clone", "busboy", "@types/connect", "estree-util-is-identifier-name", "real-require", "tailwind-merge", "streamsearch", "markdown-table", "secure-json-parse", "@next/swc-linux-x64-gnu", "@types/jsonwebtoken", "stream-shift", "micromark-extension-gfm-table", "mitt", "object-is", "http-proxy-middleware", "webpack-dev-middleware", "@smithy/md5-js", "load-json-file", "events-universal", "magicast", "mdast-util-gfm-table", "postcss-modules-local-by-default", "denque", "@parcel/watcher", "yoctocolors-cjs", "globrex", "icss-utils", "get-uri", "mdast-util-gfm-task-list-item", "os-tmpdir", "@babel/plugin-transform-regexp-modifiers", "hash.js", "@aws-sdk/middleware-expect-continue", "babel-loader", "decode-uri-component", "style-to-js", "compress-commons", "mdast-util-mdx-jsx", "@babel/plugin-transform-runtime", "@radix-ui/react-slot", "postcss-modules-values", "http2-wrapper", "file-uri-to-path", "boxen", "@inquirer/prompts", "defu", "uc.micro", "unique-string", "js-cookie", "@types/use-sync-external-store", "detect-node", "@js-sdsl/ordered-map", "@octokit/plugin-rest-endpoint-methods", "tailwindcss-animate", "react-router", "@babel/plugin-transform-dynamic-import", "dateformat", "duplexer", "micromark-extension-gfm-footnote", "http-proxy", "clone-deep", "npm-normalize-package-bin", "remark-stringify", "is-accessor-descriptor", "pretty-ms", "colors", "stack-trace", "mdast-util-gfm", "@types/normalize-package-data", "react-day-picker", "encoding-sniffer", "@smithy/hash-blob-browser", "web-vitals", "@types/yauzl", "parse5-parser-stream", "tsconfck", "mdurl", "mkdirp-classic", "@szmarczak/http-timer", "atomic-sleep", "@inquirer/select", "micromark-extension-gfm-tagfilter", "buffer-equal-constant-time", "aws4", "micromark-extension-gfm-strikethrough", "@sentry/core", "p-queue", "@babel/preset-react", "websocket-extensions", "@inquirer/input", "verror", "node-abi", "@babel/plugin-transform-react-jsx-development", "@aws-sdk/middleware-location-constraint", "mdast-util-gfm-strikethrough", "micromark-extension-gfm-task-list-item", "validator", "mdast-util-mdxjs-esm", "postcss-modules-extract-imports", "mlly", "underscore", "@opentelemetry/instrumentation-http", "is-data-descriptor", "@jest/pattern", "prismjs", "big-integer", "http-signature", "async-retry", "lazystream", "url", "@types/geojson", "@babel/plugin-transform-react-pure-annotations", "@jest/diff-sequences", "micromark-extension-gfm", "stackframe", "serialize-error", "@babel/plugin-bugfix-firefox-class-in-computed-class-key", "fastest-levenshtein", "whatwg-fetch", "readdir-glob", "axe-core", "bindings", "@inquirer/expand", "strtok3", "xml", "@smithy/chunked-blob-reader-native", "detect-indent", "mdast-util-gfm-autolink-literal", "sass", "acorn-import-phases", "@smithy/hash-stream-node", "simple-get", "change-case", "@vue/shared", "assert-plus", "cacheable-lookup", "defer-to-connect", "form-data-encoder", "@opentelemetry/instrumentation-mongodb", "are-we-there-yet", "react-fast-compare", "openai", "ts-jest", "@inquirer/editor", "error-stack-parser", "@inquirer/number", "@opentelemetry/instrumentation-graphql", "markdown-it", "@opentelemetry/instrumentation-pg", "micromark-extension-gfm-autolink-literal", "rolldown", "winston", "strip-literal", "@cspotcode/source-map-support", "common-tags", "yoctocolors", "@babel/helper-split-export-declaration", "has-value", "vite-node", "@opentelemetry/instrumentation-mongoose", "@emotion/serialize", "@types/node-fetch", "node-exports-info", "@opentelemetry/instrumentation-mysql", "hastscript", "agentkeepalive", "formidable", "@popperjs/core", "@opentelemetry/sdk-trace-node", "aproba", "jsprim", "typedarray-to-buffer", "fecha", "ts-dedent", "clean-css", "lodash.sortby", "@emotion/sheet", "@opentelemetry/instrumentation-generic-pool", "generator-function", "@hapi/topo", "@types/trusted-types", "simple-concat", "@emotion/cache", "repeat-string", "@smithy/chunked-blob-reader", "highlight.js", "d3-dispatch", "lint-staged", "@inquirer/rawlist", "bidi-js", "@opentelemetry/instrumentation-hapi", "remark-gfm", "@opentelemetry/instrumentation-connect", "delegates", "ansi-align", "snake-case", "token-types", "hash-base", "fork-ts-checker-webpack-plugin", "mdast-util-gfm-footnote", "react-router-dom", "logform", "isstream", "has-values", "fs-monkey", "@emotion/utils", "@opentelemetry/instrumentation-fs", "@radix-ui/react-toggle-group", "@emotion/weak-memoize", "caseless", "@babel/plugin-transform-explicit-resource-management", "style-loader", "@opentelemetry/instrumentation-lru-memoizer", "@tailwindcss/postcss", "aws-sign2", "hast-util-parse-selector", "@vitest/coverage-v8", "sshpk", "teeny-request", "socket.io-parser", "upath", "redux-thunk", "winston-transport", "bs-logger", "mdast-util-mdx-expression", "triple-beam", "h3", "cluster-key-slot", "joi", "@inquirer/password", "@nolyfill/is-core-module", "@opentelemetry/instrumentation-knex", "tabbable", "is-regexp", "dashdash", "json-parse-better-errors", "@ai-sdk/provider-utils", "@csstools/css-syntax-patches-for-csstree", "getpass", "@opentelemetry/exporter-trace-otlp-http", "@aws/lambda-invoke-store", "@inquirer/search", "preact", "@types/pg-pool", "base64-arraybuffer", "@vue/compiler-core", "react-markdown", "is-node-process", "@opentelemetry/instrumentation-ioredis", "jsonparse", "external-editor", "superagent", "perfect-debounce", "@anthropic-ai/sdk", "@noble/curves", "temp-dir", "gauge", "@opentelemetry/instrumentation-amqplib", "stable-hash", "tsutils", "webpack-merge", "symbol-observable", "@cloudflare/kv-asset-handler", "mdast-util-find-and-replace", "@opentelemetry/instrumentation-tedious", "node-abort-controller", "@types/minimatch", "jest-environment-jsdom", "@ai-sdk/provider", "strict-event-emitter", "@aws-crypto/supports-web-crypto", "@cloudflare/workerd-linux-64", "miniflare", "humanize-ms", "builtin-modules", "@aws-crypto/crc32", "@types/mysql", "citty", "@types/triple-beam", "@opentelemetry/instrumentation-mysql2", "eslint-config-next", "idb", "@esbuild/linux-arm64", "@parcel/watcher-linux-x64-glibc", "@vue/compiler-dom", "@sentry-internal/replay-canvas", "d3-selection", "registry-auth-token", "debounce", "one-time", "@aws-sdk/signature-v4-multi-region", "@supabase/realtime-js", "is-ci", "@smithy/eventstream-serde-browser", "camelcase-keys", "tagged-tag", "ioredis", "postgres-bytea", "lodash.isequal", "d3-drag", "gzip-size", "is-reference", "@babel/plugin-syntax-decorators", "eslint-utils", "query-string", "color-support", "retry-request", "punycode.js", "@opentelemetry/redis-common", "@supabase/auth-js", "@types/cors", "@supabase/storage-js", "table", "is-lambda", "@fastify/busboy", "dezalgo", "npmlog", "@babel/plugin-syntax-dynamic-import", "enabled", "@types/d3-scale", "resolve-alpn", "@emotion/babel-plugin", "@types/http-proxy", "@supabase/supabase-js", "@mswjs/interceptors", "unenv", "d3-transition", "kuler", "@supabase/postgrest-js", "pidtree", "@reduxjs/toolkit", "jquery", "mri", "vitefu", "@opentelemetry/instrumentation-koa", "@formatjs/intl-localematcher", "get-port", "@rolldown/binding-linux-x64-gnu", "wide-align", "fn.name", "@isaacs/balanced-match", "loglevel", "create-jest", "@jest/get-type", "marked", "ohash", "jsonpointer", "@sentry-internal/feedback", "global-dirs", "@supabase/functions-js", "vite-tsconfig-paths", "to-fast-properties", "is-installed-globally", "@types/http-cache-semantics", "@babel/plugin-transform-react-display-name", "@babel/helper-simple-access", "@babel/plugin-syntax-flow", "obuf", "eslint-plugin-react-hooks", "duplexer2", "@azure/abort-controller", "outvariant", "stream-browserify", "@emotion/react", "d3-zoom", "engine.io-parser", "lodash.isarguments", "ts-morph", "fast-check", "napi-build-utils", "lodash.castarray", "for-in", "selfsigned", "ast-v8-to-istanbul", "cross-env", "postcss-loader", "text-hex", "prebuild-install", "connect-history-api-fallback", "asn1.js", "@tybys/wasm-util", "envinfo", "stdin-discarder", "registry-url", "@asamuzakjp/nwsapi", "youch", "@types/react-transition-group", "to-buffer", "smol-toml", "proto3-json-serializer", "expand-template", "lodash.get", "netmask", "forever-agent", "proto-list", "json-schema-to-ts", "libphonenumber-js", "webpack-dev-server", "redis-errors", "html-void-elements", "html-minifier-terser", "postcss-discard-duplicates", "postgres-array", "d3-geo", "robust-predicates", "@vue/compiler-sfc", "joycon", "rou3", "youch-core", "@types/aws-lambda", "config-chain", "lodash.clonedeep", "launch-editor", "wildcard", "clone-response", "stringify-object", "@babel/plugin-proposal-decorators", "@opentelemetry/instrumentation-express", "browserify-zlib", "raf", "urlpattern-polyfill", "remove-trailing-separator", "node-gyp-build-optional-packages", "destr", "arr-diff", "@emotion/use-insertion-effect-with-fallbacks", "msgpackr", "redis-parser", "@ts-morph/common", "postcss-minify-selectors", "@types/glob", "postcss-discard-empty", "filesize", "vscode-uri", "fast-copy", "postcss-merge-rules", "get-stdin", "@opentelemetry/instrumentation-dataloader", "filter-obj", "map-cache", "terminal-link", "@opentelemetry/instrumentation-undici", "cookiejar", "void-elements", "@graphql-tools/merge", "moment-timezone", "dns-packet", "cssnano", "import-meta-resolve", "@puppeteer/browsers", "core-js-pure", "github-from-package", "has", "@graphql-tools/schema", "sass-loader", "postcss-merge-longhand", "@sentry/react", "postcss-minify-params", "postcss-convert-values", "@angular-devkit/core", "strict-uri-encode", "@babel/helper-function-name", "ecc-jsbn", "@sentry-internal/browser-utils", "blake3-wasm", "traverse", "@jsonjoy.com/util", "@sentry-internal/replay", "trim-newlines", "select-hose", "@types/tedious", "@yarnpkg/lockfile", "@radix-ui/react-slider", "postcss-svgo", "@types/jsdom", "@azure/msal-common", "import-lazy", "assert", "set-value", "bare-url", "spdy-transport", "mini-css-extract-plugin", "html-url-attributes", "postcss-calc", "cssnano-preset-default", "@babel/plugin-transform-flow-strip-types", "postcss-normalize-whitespace", "stylehacks", "@tootallnate/quickjs-emscripten", "batch", "is-what", "colord", "es6-promise", "ansi-html-community", "opener", "console-control-strings", "@vue/compiler-ssr", "@tanstack/history", "@vitejs/plugin-react-swc", "postcss-normalize-url", "telecom-mas-agent", "@faker-js/faker", "node-fetch-native", "has-unicode", "@dnd-kit/core", "@types/mdx", "tunnel", "@babel/plugin-transform-duplicate-named-capturing-groups-regex", "url-join", "@dnd-kit/utilities", "postcss-normalize-timing-functions", "@opentelemetry/exporter-logs-otlp-http", "@aws-sdk/client-sts", "crypto-js", "relateurl", "w3c-keyname", "devtools-protocol", "spdy", "lucide-react", "bcrypt-pbkdf", "sha.js", "postcss-unique-selectors", "@sentry/cli", "postcss-normalize-display-values", "@csstools/selector-specificity", "eventemitter2", "@cloudflare/unenv-preset", "@aws-sdk/util-format-url", "@types/cookie", "@babel/helper-environment-visitor", "copy-anything", "vfile-location", "postcss-reduce-transforms", "postcss-discard-overridden", "xdg-basedir", "xmlbuilder2", "@isaacs/fs-minipass", "@google-cloud/paginator", "type", "jspdf", "css-declaration-sorter", "fast-content-type-parse", "uint8array-extras", "postcss-colormin", "srvx", "pdfjs-dist", "@formatjs/ecma402-abstract", "nice-try", "html-webpack-plugin", "effect", "giget", "serve-index", "upper-case", "@opentelemetry/otlp-grpc-exporter-base", "postcss-ordered-values", "shallowequal", "package-manager-detector", "postcss-reduce-initial", "postcss-discard-comments", "homedir-polyfill", "postcss-minify-gradients", "@standard-schema/spec", "rw", "functional-red-black-tree", "concurrently", "headers-polyfill", "untildify", "@svgr/babel-plugin-transform-react-native-svg", "@opentelemetry/instrumentation-redis", "jwt-decode", "parse-passwd", "@opentelemetry/propagator-jaeger", "warning", "postcss-normalize-charset", "@types/d3-zoom", "@svgr/babel-plugin-svg-dynamic-title", "expand-tilde", "@babel/plugin-proposal-class-properties", "postcss-minify-font-values", "multicast-dns", "stream-events", "sockjs", "hpack.js", "@svgr/plugin-jsx", "nodemailer", "react-docgen", "@tanstack/router-core", "postcss-normalize-unicode", "postcss-normalize-positions", "@rollup/plugin-node-resolve", "@svgr/babel-plugin-svg-em-dimensions", "@formatjs/fast-memoize", "adm-zip", "code-block-writer", "postcss-normalize-string", "queue", "@svgr/hast-util-to-babel-ast", "upper-case-first", "d3-hierarchy", "@mdx-js/react", "rc9", "pretty-error", "wbuf", "lodash.truncate", "thunky", "atob", "postcss-normalize-repeat-style", "renderkid", "lodash.flatten", "throat", "@formatjs/icu-skeleton-parser", "has-ansi", "@npmcli/agent", "@date-fns/tz", "@tanstack/router-plugin", "array-unique", "@svgr/babel-preset", "@formatjs/icu-messageformat-parser", "caniuse-api", "empathic", "safe-regex", "tempy", "seroval", "querystring", "intl-messageformat", "@opentelemetry/propagator-b3", "@tanstack/react-virtual", "@svgr/babel-plugin-remove-jsx-empty-expression", "msgpackr-extract", "@jsonjoy.com/json-pack", "help-me", "tldts", "@types/statuses", "request", "@babel/plugin-transform-react-jsx-self", "@parcel/watcher-linux-x64-musl", "@svgr/babel-plugin-replace-jsx-attribute-value", "ignore-walk", "@tanstack/router-generator", "md5", "@types/long", "@esbuild/darwin-arm64", "eslint-plugin-jest", "bplist-parser", "@jest/snapshot-utils", "@tanstack/router-utils", "conventional-commits-parser", "@svgr/core", "delaunator", "get-value", "stubs", "arr-union", "@types/d3-transition", "@angular-devkit/schematics", "@types/d3-selection", "isomorphic-ws", "c12", "@babel/plugin-syntax-bigint", "@paralleldrive/cuid2", "del", "har-validator", "@types/request", "@azure/msal-node", "@dnd-kit/accessibility", "charenc", "@jsonjoy.com/base64", "@graphql-typed-document-node/core", "d3-quadtree", "@types/mdurl", "@tanstack/virtual-file-routes", "@types/keyv", "throttleit", "nypm", "@dnd-kit/sortable", "supertest", "dependency-graph", "@svgr/babel-plugin-add-jsx-attribute", "oauth-sign", "ramda", "chromium-bidi", "elliptic", "ripemd160", "@octokit/rest", "@svgr/babel-plugin-remove-jsx-attribute", "@shikijs/types", "configstore", "@types/connect-history-api-fallback", "@types/d3-time-format", "arch", "@types/doctrine", "shimmer", "utila", "expand-brackets", "engine.io", "stackback", "sort-keys", "npm-install-checks", "@tanstack/store", "@types/responselike", "@types/html-minifier-terser", "@sentry/opentelemetry", "@opentelemetry/instrumentation-kafkajs", "npm-bundled", "node-emoji", "npm-pick-manifest", "bonjour-service", "prr", "@shikijs/engine-oniguruma", "node-pty", "append-field", "json-stable-stringify", "web-namespaces", "promise-inflight", "layout-base", "split-on-first", "@esbuild/win32-x64", "@types/d3-drag", "@asamuzakjp/dom-selector", "@types/sockjs", "mocha", "connect", "@jsonjoy.com/buffers", "@npmcli/promise-spawn", "@types/js-yaml", "d3-force", "resolve-dir", "@rollup/plugin-commonjs", "proper-lockfile", "@rushstack/eslint-patch", "@types/markdown-it", "@babel/plugin-proposal-object-rest-spread", "local-pkg", "d3-delaunay", "pinkie", "@ioredis/commands", "create-hash", "use-sidecar", "react-docgen-typescript", "hast-util-from-parse5", "@discoveryjs/json-ext", "klona", "@inquirer/checkbox", "@npmcli/git", "socket.io", "npm-packlist", "@types/serve-index", "is-module", "seroval-plugins", "conventional-changelog-angular", "find-root", "@types/minimist", "har-schema", "cssnano-utils", "is-retry-allowed", "@msgpackr-extract/msgpackr-extract-linux-x64", "@sentry/node-core", "des.js", "@bufbuild/protobuf", "mustache", "lodash.escaperegexp", "handle-thing", "q", "@types/fs-extra", "jsonify", "@babel/helper-hoist-variables", "url-template", "errno", "regexpp", "@aws-sdk/s3-request-presigner", "assign-symbols", "exit-x", "@opentelemetry/exporter-metrics-otlp-http", "path-case", "csv-parse", "limiter", "crypt", "extglob", "fbjs", "text-decoder", "@vercel/oidc", "@aws-crypto/crc32c", "cron-parser", "i18next", "pinkie-promise", "@socket.io/component-emitter", "sourcemap-codec", "@esbuild/darwin-x64", "@opentelemetry/exporter-trace-otlp-grpc", "svg-parser", "@borewit/text-codec", "@types/d3-delaunay", "base64id", "basic-auth", "slugify", "hmac-drbg", "minimist-options", "vscode-languageserver-types", "qrcode", "http-deceiver", "lighthouse-logger", "@apidevtools/json-schema-ref-parser", "quansync", "socket.io-adapter", "@types/bonjour", "@mapbox/node-pre-gyp", "@types/d3-format", "@tanstack/start-client-core", "@tanstack/start-storage-context", "@tanstack/start-server-core", "brorand", "@tanstack/start-plugin-core", "sentence-case", "@tanstack/react-start-server", "@tanstack/react-start-client", "object.pick", "d3-dsv", "@types/d3-scale-chromatic", "js-base64", "@sideway/formula", "xml-js", "es-get-iterator", "nullthrows", "walk-up-path", "ts-loader", "lodash.throttle", "katex", "constant-case", "@dabh/diagnostics", "@tanstack/start-fn-stubs", "get-own-enumerable-property-symbols", "use-callback-ref", "@azure/msal-browser", "@tanstack/table-core", "graphql-tag", "string.prototype.includes", "@tanstack/react-table", "tsconfig-paths-webpack-plugin", "es6-symbol", "socket.io-client", "@azure/core-client", "is-url", "@types/hoist-non-react-statics", "workerpool", "needle", "formdata-node", "@types/sinonjs__fake-timers", "es5-ext", "use-isomorphic-layout-effect", "@types/validator", "es6-error", "bson", "dom-converter", "hast-util-to-parse5", "source-map-resolve", "isbinaryfile", "header-case", "capital-case", "css-line-break", "npm-registry-fetch", "strip-eof", "split", "@types/superagent", "on-exit-leak-free", "engine.io-client", "googleapis-common", "d3-polygon", "package-json", "d3-axis", "@types/d3-hierarchy", "react-style-singleton", "@types/caseless", "@trysound/sax", "@shikijs/langs", "postcss-safe-parser", "pkce-challenge", "is-path-cwd", "next-tick", "unzipper", "compare-versions", "google-gax", "semver-compare", "minimalistic-crypto-utils", "@sindresorhus/merge-streams", "chrome-launcher", "html2canvas", "@types/pako", "@actions/http-client", "@napi-rs/canvas", "nodemon", "ignore-by-default", "decamelize-keys", "@mui/types", "deprecation", "@emotion/styled", "prosemirror-transform", "regenerator-transform", "crelt", "@tanstack/react-start", "d", "compare-func", "@sentry/cli-linux-x64", "lodash.difference", "@types/d3-force", "dataloader", "union-value", "@svgr/babel-plugin-transform-svg-component", "motion", "confusing-browser-globals", "@opentelemetry/exporter-trace-otlp-proto", "jwks-rsa", "@shikijs/themes", "hast-util-raw", "d3-chord", "simple-update-notifier", "@types/cookiejar", "@babel/plugin-proposal-optional-chaining", "@isaacs/brace-expansion", "@types/node-forge", "lodash.union", "is-relative", "standard-as-callback", "touch", "path-is-inside", "webpack-cli", "vue", "portfinder", "@opentelemetry/exporter-metrics-otlp-proto", "source-map-url", "tree-dump", "d3", "html-tags", "JSONStream", "thingies", "file-loader", "@graphql-codegen/plugin-helpers", "tinycolor2", "split-string", "@sentry/node", "lodash.isfunction", "copy-webpack-plugin", "unc-path-regex", "is-unc-path", "resize-observer-polyfill", "cipher-base", "@jsonjoy.com/json-pointer", "is-absolute", "@rollup/plugin-replace", "@types/cacheable-request", "tsscmp", "hookable", "@azure/core-tracing", "is-property", "@types/luxon", "pbkdf2", "findup-sync", "camelize", "es6-iterator", "@lukeed/csprng", "@npmcli/run-script", "call-me-maybe", "unbzip2-stream", "hard-rejection", "vscode-languageserver-textdocument", "generate-function", "@ai-sdk/gateway", "pumpify", "lru-memoizer", "puppeteer-core", "address", "@shikijs/core", "chart.js", "pkg-up", "@opentelemetry/exporter-metrics-otlp-grpc", "comment-json", "@types/d3", "yup", "shiki", "unist-util-remove-position", "@prisma/get-platform", "ext", "hyperdyperid", "metro-source-map", "array-ify", "lodash.snakecase", "@google-cloud/storage", "git-raw-commits", "array-back", "metro-runtime", "@sentry/types", "import-from", "plist", "browserify-aes", "to-object-path", "rehype-raw", "lodash.mergewith", "npm", "@npmcli/node-gyp", "get-func-name", "undefsafe", "stream-buffers", "fault", "@sentry/babel-plugin-component-annotate", "prosemirror-commands", "escape-goat", "hast-util-is-element", "@rolldown/binding-linux-x64-musl", "d3-brush", "@vue/reactivity", "metro-symbolicate", "unset-value", "@esbuild/linux-loong64", "d3-contour", "title-case", "builtins", "adler-32", "ob1", "@babel/plugin-proposal-nullish-coalescing-operator", "@types/d3-geo", "is-nan", "@prisma/debug", "css-color-keywords", "esbuild-register", "pstree.remy", "typical", "@tanstack/react-start-rsc", "@turf/helpers", "crypto-browserify", "oxc-parser", "storybook", "jsonpath-plus", "toposort", "polished", "event-emitter", "prosemirror-view", "webpack-bundle-analyzer", "dset", "ip-regex", "morgan", "@types/supertest", "@jsonjoy.com/codegen", "mixin-deep", "compute-scroll-into-view", "object-visit", "@svgr/plugin-svgo", "@types/d3-axis", "pseudomap", "@aws-sdk/client-cognito-identity", "repeat-element", "@tiptap/pm", "d3-random", "@tiptap/extension-paragraph", "@types/estree-jsx", "@cloudflare/vite-plugin", "constants-browserify", "cfb", "ssf", "acorn-import-assertions", "@jest/create-cache-key-function", "os-homedir", "async-limiter", "html-parse-stringify", "@types/d3-random", "@types/d3-fetch", "prosemirror-state", "@types/d3-brush", "swr", "mysql2", "svg-pathdata", "@npmcli/installed-package-contents", "@types/d3-dsv", "@types/shimmer", "@opentelemetry/exporter-prometheus", "@expo/json-file", "@types/d3-dispatch", "metro-transform-worker", "metro-cache-key", "helmet", "metro", "@esbuild/linux-ppc64", "@jsdevtools/ono", "@clack/core", "@base44/vite-plugin", "copy-descriptor", "global-directory", "css-to-react-native", "@flmngr/flmngr-react", "@whatwg-node/node-fetch", "@tiptap/extension-italic", "ajv-draft-04", "arr-flatten", "tiny-warning", "browserify-sign", "@esbuild/freebsd-x64", "fragment-cache", "metro-transform-plugins", "common-path-prefix", "xmlhttprequest-ssl", "miller-rabin", "browserify-rsa", "@vue/runtime-core", "deepmerge-ts", "prepend-http", "esniff", "@vue/runtime-dom", "urix", "notifications-node-client", "copy-to-clipboard", "mnemonist", "@types/methods", "valibot", "path-root", "@shikijs/engine-javascript", "prosemirror-model", "@remix-run/router", "@floating-ui/react", "https-browserify", "@esbuild/sunos-x64", "use", "resolve-url", "stream-http", "yargs-unparser", "d3-fetch", "@azure/core-rest-pipeline", "metro-cache", "cache-base", "papaparse", "codepage", "ai", "react-dropzone", "graphql-ws", "parse-asn1", "prosemirror-tables", "v8-compile-cache", "xlsx", "fstream", "@storybook/react", "@tiptap/extension-strike", "diffie-hellman", "@open-draft/logger", "quick-format-unescaped", "source-map-loader", "canvg", "@actions/core", "@nestjs/core", "hasha", "buffers", "class-utils", "snapdragon", "file-selector", "bottleneck", "path-root-regex", "@aws-crypto/sha1-browser", "collection-visit", "fbjs-css-vars", "@esbuild/win32-arm64", "marky", "frac", "@vue/server-renderer", "shelljs", "wmf", "pascalcase", "github-slugger", "jsdoc-type-pratt-parser", "@nestjs/common", "create-hmac", "regex-not", "@tiptap/extension-heading", "@kwsites/file-exists", "puppeteer", "parse-filepath", "redis", "posix-character-classes", "domain-browser", "nanomatch", "@lovable.dev/vite-tanstack-config", "metro-config", "p-defer", "@tiptap/extension-bold", "pgpass", "quickselect", "@types/phoenix", "@google-cloud/promisify", "auto-bind", "fuse.js", "@mui/system", "@leichtgewicht/ip-codec", "word", "static-extend", "@types/d3-polygon", "regex", "@tiptap/extension-bubble-menu", "conventional-changelog-conventionalcommits", "@babel/eslint-parser", "@babel/runtime-corejs3", "base", "format", "fast-redact", "@tiptap/extension-bullet-list", "known-css-properties", "@sideway/pinpoint", "@esbuild/linux-ia32", "@types/prettier", "snapdragon-node", "@graphql-codegen/visitor-plugin-common", "is-network-error", "@tiptap/extension-blockquote", "@esbuild/linux-riscv64", "@esbuild/netbsd-x64", "public-encrypt", "to-regex", "@google/genai", "@tiptap/extension-ordered-list", "object-copy", "@sentry/utils", "multer", "@slack/types", "source-list-map", "yaml-ast-parser", "map-visit", "@azure/core-util", "metro-file-map", "@tiptap/extension-code-block", "object.getownpropertydescriptors", "@graphql-tools/batch-execute", "@speed-highlight/core", "@vitest/ui", "@webpack-cli/serve", "@esbuild/openbsd-x64", "@esbuild/android-arm64", "pvutils", "@esbuild/freebsd-arm64", "@babel/plugin-proposal-numeric-separator", "chainsaw", "stable", "@types/d3-chord", "snapdragon-util", "latest-version", "@tiptap/extension-list-item", "harmony-reflect", "swagger-ui-dist", "attr-accept", "is-npm", "@babel/helper-builder-binary-assignment-operator-visitor", "array-timsort", "lodash.flattendeep", "vm-browserify", "@swc/core-linux-x64-musl", "@pnpm/network.ca-file", "selderee", "@storybook/addon-docs", "@esbuild/android-x64", "@esbuild/linux-mips64el", "chevrotain", "oniguruma-to-es", "browser-stdout", "bcryptjs", "@microsoft/tsdoc", "case-sensitive-paths-webpack-plugin", "simple-git", "find-up-simple", "@firebase/util", "@kurkle/color", "@webpack-cli/info", "hookified", "querystring-es3", "console-browserify", "regex-recursion", "@tiptap/extension-link", "tty-browserify", "@esbuild/android-arm", "index-to-position", "dargs", "os-browserify", "sinon", "less", "react-i18next", "fast-wrap-ansi", "@pnpm/config.env-replace", "stackblur-canvas", "@babel/plugin-proposal-private-methods", "binary", "class-transformer", "@whatwg-node/fetch", "property-expr", "@babel/register", "typed-query-selector", "metro-babel-transformer", "md5.js", "memory-fs", "builtin-status-codes", "@fast-csv/format", "hyphenate-style-name", "fast-querystring", "@volar/language-core", "ip", "@redis/client", "is-builtin-module", "astring", "@esbuild/linux-arm", "@babel/plugin-syntax-export-namespace-from", "is-lower-case", "@esbuild/linux-s390x", "pvtsutils", "@rollup/plugin-babel", "@types/d3-contour", "rettime", "@opentelemetry/instrumentation-nestjs-core", "asn1js", "linkifyjs", "browser-process-hrtime", "@types/whatwg-url", "jsep", "@aws-sdk/credential-providers", "@selderee/plugin-htmlparser2", "regex-parser", "@npmcli/package-json", "number-is-nan", "default-gateway", "infer-owner", "timers-browserify", "is-upper-case", "comment-parser", "fast-csv", "@storybook/theming", "styled-components", "@graphql-tools/load", "html-to-text", "@oxc-parser/binding-linux-x64-gnu", "react-lifecycles-compat", "swap-case", "@tokenizer/token", "adjust-sourcemap-loader", "msw", "stylelint", "isomorphic-fetch", "@actions/io", "vscode-languageserver-protocol", "postcss-media-query-parser", "aws-sdk", "lodash.groupby", "@mui/styled-engine", "@react-native/dev-middleware", "parseley", "code-point-at", "async-mutex", "@esbuild/aix-ppc64", "jest-serializer", "resolve-url-loader", "@slack/web-api", "babel-plugin-syntax-hermes-parser", "@graphql-tools/optimize", "@tiptap/extension-code", "identity-obj-proxy", "@tiptap/extension-document", "crossws", "buffer-xor", "filenamify", "@azure/core-paging", "natural-compare-lite", "jest-junit", "for-own", "brotli", "@graphql-tools/relay-operation-optimizer", "parse-node-version", "generic-pool", "semver-diff", "@webpack-cli/configtest", "@csstools/media-query-list-parser", "matcher", "better-opn", "date-fns-tz", "@tiptap/extension-gapcursor", "from2", "@braintree/sanitize-url", "randexp", "array-uniq", "yarn", "@expo/plist", "@tufjs/models", "@mui/core-downloads-tracker", "@chevrotain/types", "@tiptap/starter-kit", "@esbuild/win32-ia32", "base-x", "@mui/utils", "lodash.isnil", "class-validator", "sqlstring", "object-treeify", "cachedir", "react-error-boundary", "@vue/devtools-api", "react-devtools-core", "lowlight", "vscode-languageserver", "uid", "lodash.startcase", "@slack/logger", "http-status-codes", "fast-decode-uri-component", "metro-minify-terser", "jmespath", "@mui/private-theming", "pino-pretty", "@svgr/webpack", "@radix-ui/react-toolbar", "@jsep-plugin/assignment", "@commitlint/types", "postgres", "@keyv/serialize", "fast-sha256", "tuf-js", "earcut", "@sinonjs/samsam", "openid-client", "create-ecdh", "@types/sizzle", "cookie-parser", "update-notifier", "pixelmatch", "react-icons", "iterare", "toggle-selection", "@tiptap/extension-underline", "@iconify/types", "@graphql-tools/graphql-tag-pluck", "svg-tags", "pacote", "lodash.kebabcase", "@azure/logger", "@ardatan/relay-compiler", "temp", "@mui/material", "rope-sequence", "moo", "browserify-cipher", "@prisma/config", "editorconfig", "nx", "chalk-template", "util.promisify", "p-event", "w3c-hr-time", "spark-md5", "css-minimizer-webpack-plugin", "turbo", "es-array-method-boxes-properly", "cross-inspect", "history", "supercluster", "kdbush", "is-utf8", "@stablelib/base64", "@fast-csv/parse", "@kwsites/promise-deferred", "@clack/prompts", "@expo/config-plugins", "jju", "cosmiconfig-typescript-loader", "react-select", "@commitlint/execute-rule", "uncrypto", "@commitlint/load", "is-text-path", "@types/linkify-it", "bare-os", "@tiptap/react", "@react-native/debugger-frontend", "@chevrotain/cst-dts-gen", "googleapis", "lodash.isundefined", "@module-federation/sdk", "@google-cloud/projectify", "anser", "devalue", "hast-util-to-text", "@octokit/plugin-request-log", "@antfu/install-pkg", "@sigstore/bundle", "detect-file", "text-extensions", "globjoin", "ulid", "eslint-plugin-testing-library", "lower-case-first", "workbox-core", "filename-reserved-regex", "@firebase/logger", "prosemirror-schema-list", "pupa", "text-segmentation", "@opentelemetry/instrumentation-grpc", "safe-regex2", "@pmmmwh/react-refresh-webpack-plugin", "mdast-util-definitions", "@stripe/stripe-js", "@biomejs/biome", "eslint-plugin-unused-imports", "@jsep-plugin/regex", "@react-aria/interactions", "@aws-sdk/credential-provider-cognito-identity", "buffer-indexof-polyfill", "@redis/search", "date-fns-jalali", "@graphql-tools/executor-http", "@commitlint/resolve-extends", "@react-native/normalize-colors", "@vue/language-core", "@typescript-eslint/experimental-utils", "prosemirror-markdown", "@types/scheduler", "@anthropic-ai/claude-code", "archy", "webpack-node-externals", "@tufjs/canonical-json", "tinyqueue", "@react-aria/focus", "strip-comments", "babel-runtime", "@graphql-tools/executor", "sanitize-html", "@storybook/csf", "cookies", "is-electron", "wait-on", "@octokit/auth-app", "leac", "find-versions", "@anthropic-ai/claude-code-linux-x64", "date-format", "potpack", "@volar/source-map", "@sigstore/tuf", "istanbul-lib-hook", "@repeaterjs/repeater", "@module-federation/webpack-bundler-runtime", "semver-regex", "@redis/json", "hast-util-from-html", "birpc", "@radix-ui/react-use-rect", "@chevrotain/gast", "find-yarn-workspace-root", "@commitlint/rules", "@nicolo-ribaudo/eslint-scope-5-internals", "@types/webidl-conversions", "@tanstack/query-devtools", "sigstore", "btoa", "fd-package-json", "@sigstore/sign", "@lezer/lr", "jpeg-js", "graphql-config", "@commitlint/to-lines", "@aws-sdk/client-sqs", "@redis/time-series", "peek-readable", "@commitlint/cli", "vinyl", "graphql-request", "fromentries", "@yarnpkg/parsers", "react-easy-router", "@react-aria/ssr", "@tiptap/extension-horizontal-rule", "@types/js-cookie", "lazy-cache", "vlq", "@types/bunyan", "@react-types/shared", "prosemirror-dropcursor", "read-cmd-shim", "@opentelemetry/exporter-zipkin", "jest-jasmine2", "postcss-nesting", "toml", "replace-ext", "prosemirror-schema-basic", "sparse-bitfield", "p-is-promise", "@prisma/fetch-engine", "refractor", "postcss-custom-media", "read-package-json-fast", "postcss-custom-properties", "multimatch", "@codemirror/view", "@radix-ui/react-use-effect-event", "@aws-sdk/middleware-sdk-sqs", "array-differ", "@sideway/address", "ts-toolbelt", "sade", "workbox-expiration", "roarr", "@esbuild/openbsd-arm64", "@scarf/scarf", "nyc", "cytoscape", "prisma", "@typespec/ts-http-runtime", "@graphql-tools/executor-common", "prosemirror-gapcursor", "find-my-way", "exit-hook", "@commitlint/lint", "oauth4webapi", "types-registry", "@react-stately/utils", "@types/ssh2", "workbox-navigation-preload", "mongodb", "@graphql-tools/json-file-loader", "ofetch", "workbox-google-analytics", "@prisma/engines-version", "workbox-streams", "workbox-background-sync", "workbox-strategies", "@storybook/core-events", "unstorage", "fastify", "url-parse-lax", "@remirror/core-constants", "@biomejs/cli-linux-x64", "boolean", "collapse-white-space", "@expo/config-types", "@firebase/database-types", "@nx/devkit", "executable", "array.prototype.reduce", "@nestjs/platform-express", "xpath", "global", "value-or-promise", "prosemirror-trailing-node", "@sigstore/verify", "get-port-please", "@redis/bloom", "@storybook/preview-api", "prosemirror-changeset", "@cypress/request", "js-beautify", "muggle-string", "unixify", "next", "@commitlint/ensure", "superjson", "jest-watch-typeahead", "@graphql-tools/wrap", "@commitlint/config-conventional", "koa", "eslint-plugin-storybook", "@commitlint/read", "postcss-selector-not", "workbox-range-requests", "@commitlint/is-ignored", "postcss-custom-selectors", "utility-types", "unicode-properties", "postcss-pseudo-class-any-link", "@aws-sdk/client-secrets-manager", "postcss-color-rebeccapurple", "streamroller", "postcss-attribute-case-insensitive", "zen-observable-ts", "sonner", "estree-util-visit", "js-levenshtein", "fast-json-stringify", "iron-webcrypto", "workbox-cacheable-response", "@radix-ui/react-accordion", "eslint-import-context", "classcat", "detect-port", "jscodeshift", "@aws-sdk/client-lambda", "scroll-into-view-if-needed", "light-my-request", "fastify-plugin", "@sigstore/core", "@commitlint/format", "append-transform", "@module-federation/runtime-tools", "@aws-sdk/middleware-endpoint-discovery", "caller-path", "keygrip", "postcss-focus-visible", "@aashutoshrathi/word-wrap", "pprof-format", "@commitlint/config-validator", "@module-federation/runtime-core", "@sentry/webpack-plugin", "@graphql-tools/executor-graphql-ws", "@commitlint/message", "oniguruma-parser", "postcss-lab-function", "prosemirror-menu", "cli-progress", "@commitlint/top-level", "postcss-gap-properties", "postcss-place", "css-functions-list", "workbox-build", "@storybook/components", "is-absolute-url", "micromark-extension-mdxjs-esm", "getenv", "postcss-font-variant", "caching-transform", "cmd-shim", "@firebase/app-types", "stable-hash-x", "dd-trace", "es6-weak-map", "postcss-color-functional-notation", "evp_bytestokey", "postcss-replace-overflow-wrap", "@storybook/client-logger", "css-blank-pseudo", "cssdb", "@esbuild/netbsd-arm64", "@rollup/rollup-linux-arm64-gnu", "global-agent", "hpagent", "@opentelemetry/sql-common", "@radix-ui/react-checkbox", "ssh2", "workbox-window", "@aws-sdk/util-utf8-browser", "server-only", "@posthog/core", "@graphql-tools/delegate", "@chevrotain/utils", "@react-aria/utils", "@isaacs/ttlcache", "abstract-logging", "@babel/plugin-proposal-async-generator-functions", "patch-package", "@rollup/plugin-json", "react-textarea-autosize", "micromark-extension-mdx-jsx", "postcss-dir-pseudo-class", "@aws-sdk/lib-storage", "@zkochan/js-yaml", "seedrandom", "micromark-factory-mdx-expression", "@babel/plugin-transform-react-constant-elements", "unist-util-position-from-estree", "@firebase/auth-interop-types", "load-tsconfig", "sync-fetch", "@apideck/better-ajv-errors", "nise", "eslint-compat-utils", "postcss-resolve-nested-selector", "@gar/promisify", "workbox-routing", "@graphql-tools/code-file-loader", "glob-to-regex.js", "avvio", "@nestjs/schematics", "exsolve", "@opentelemetry/instrumentation-aws-sdk", "is-directory", "log4js", "csv-stringify", "eslint-config-airbnb-base", "prosemirror-collab", "request-progress", "istanbul-lib-processinfo", "@babel/plugin-proposal-export-default-from", "klaw-sync", "remark-mdx", "@types/multer", "async-each", "delay", "@lezer/highlight", "cypress", "localforage", "@nestjs/mapped-types", "buildcheck", "less-loader", "@open-draft/until", "passport", "@rushstack/node-core-library", "@lezer/common", "@commitlint/parse", "@azure/identity", "workbox-recipes", "@firebase/database-compat", "@drizzle-team/brocli", "strip-dirs", "@octokit/plugin-throttling", "@types/q", "postcss-color-hex-alpha", "stylelint-config-recommended", "min-document", "clipboardy", "dc-polyfill", "ansi-html", "workbox-broadcast-update", "alien-signals", "flow-enums-runtime", "axios-retry", "throttle-debounce", "postcss-preset-env", "postcss-logical", "fontkit", "linebreak", "@types/nodemailer", "css-prefers-color-scheme", "@opentelemetry/instrumentation-redis-4", "postcss-image-set-function", "node-preload", "micromark-extension-mdx-expression", "flow-parser", "@sigstore/protobuf-specs", "@types/mocha", "bs58", "@datadog/pprof", "@octokit/oauth-app", "@opentelemetry/instrumentation-winston", "package-hash", "openapi-types", "workbox-sw", "@react-native/babel-preset", "stack-generator", "spawn-wrap", "@types/sinon", "goober", "process-on-spawn", "stream-combiner", "@azure/core-lro", "@oxc-resolver/binding-linux-x64-gnu", "requireindex", "postcss-double-position-gradients", "cli-highlight", "babel-core", "@vueuse/core", "@mdx-js/mdx", "kolorist", "memorystream", "has-yarn", "systeminformation", "seq-queue", "hachure-fill", "micromark-extension-mdxjs", "@storybook/global", "@types/react-reconciler", "cpu-features", "@mermaid-js/parser", "@module-federation/error-codes", "@tanstack/react-query-devtools", "ajv-errors", "p-reduce", "@turf/meta", "micromark-extension-mdx-md", "@nx/nx-linux-x64-gnu", "@csstools/postcss-progressive-custom-properties", "release-zalgo", "@mui/icons-material", "postcss-page-break", "@nestjs/testing", "mem", "@aws-sdk/client-sso-oidc", "remeda", "@babel/plugin-proposal-logical-assignment-operators", "bun-types", "@google-cloud/firestore", "fast-json-patch", "common-ancestor-path", "async-lock", "style-mod", "@opentelemetry/instrumentation-bunyan", "forwarded-parse", "codemirror", "atomically", "array-find-index", "@storybook/channels", "@radix-ui/react-accessible-icon", "vue-demi", "eslint-plugin-n", "vue-eslint-parser", "map-or-similar", "varint", "stream-chain", "formatly", "duplexer3", "@graphql-tools/github-loader", "@types/prismjs", "cytoscape-cose-bilkent", "micromark-util-events-to-acorn", "tdigest", "@opentelemetry/instrumentation-fastify", "stream-json", "canvas", "colorspace", "tiny-emitter", "better-sqlite3", "khroma", "app-root-path", "memoizerific", "@react-native/community-cli-plugin", "@types/google.maps", "pause", "@graphql-tools/graphql-file-loader", "readable-web-to-node-stream", "ts-invariant", "buffer-alloc-unsafe", "http-assert", "@scure/base", "@rollup/rollup-linux-arm64-musl", "css-in-js-utils", "piscina", "@typescript/native-preview", "@storybook/manager-api", "convert-hrtime", "p-filter", "bintrees", "@graphql-tools/import", "gl-matrix", "@graphql-tools/executor-legacy-ws", "@opentelemetry/instrumentation-pino", "@ai-sdk/openai", "webpack-hot-middleware", "radix-ui", "jsc-safe-url", "lunr", "koa-compose", "@whatwg-node/promise-helpers", "node-html-parser", "@wry/equality", "cytoscape-fcose", "browserify-des", "@edsdk/n1ed-react", "@cucumber/messages", "@types/dompurify", "@dnd-kit/modifiers", "@electric-sql/pglite", "os-locale", "seek-bzip", "react-syntax-highlighter", "conventional-commits-filter", "@vueuse/shared", "@react-native/codegen", "@angular-devkit/architect", "@types/tmp", "postcss-focus-within", "openapi3-ts", "@sentry/nextjs", "bundle-require", "smob", "@redocly/ajv", "blob-util", "css-has-pseudo", "@octokit/auth-oauth-app", "@google-cloud/common", "monaco-editor", "is-yarn-global", "@opentelemetry/resource-detector-gcp", "prom-client", "@fastify/error", "oxlint", "file-saver", "bin-links", "v8flags", "@radix-ui/react-switch", "read", "load-esm", "eslint-plugin-promise", "firebase-admin", "@jsonjoy.com/fs-node-builtins", "columnify", "@types/whatwg-mimetype", "check-more-types", "@babel/plugin-proposal-optional-catch-binding", "bufferutil", "@sentry/browser", "@types/lodash-es", "@vitejs/plugin-vue", "nano-spawn", "buffer-alloc", "@babel/preset-flow", "@octokit/webhooks", "drizzle-kit", "@algolia/requester-node-http", "passport-strategy", "@algolia/client-search", "@playwright/test", "roughjs", "@iconify/utils", "@types/argparse", "@babel/plugin-syntax-export-default-from", "@codemirror/commands", "@radix-ui/react-form", "@surma/rollup-plugin-off-main-thread", "@react-native/virtualized-lists", "@jsonjoy.com/fs-node", "recursive-readdir", "grapheme-splitter", "unquote", "@pnpm/npm-conf", "@expo/image-utils", "@cypress/xvfb", "@opentelemetry/instrumentation-socket.io", "sanitize-filename", "fast-text-encoding", "buffer-fill", "@joshwooding/vite-plugin-react-docgen-typescript", "@rollup/plugin-terser", "bootstrap", "@csstools/postcss-is-pseudo-class", "recharts-scale", "find-replace", "@storybook/builder-vite", "@rollup/rollup-win32-x64-msvc", "http-server", "string-env-interpolation", "@types/qrcode", "map-stream", "points-on-curve", "@algolia/client-common", "google-p12-pem", "@babel/plugin-proposal-unicode-property-regex", "@aws-sdk/eventstream-handler-node", "@esbuild/openharmony-arm64", "@envelop/core", "@tanstack/virtual-core", "@rollup/rollup-darwin-arm64", "@csstools/postcss-cascade-layers", "svix", "unfetch", "utf-8-validate", "@algolia/requester-browser-xhr", "postcss-values-parser", "@csstools/postcss-normalize-display-values", "simple-plist", "@next/swc-linux-x64-musl", "@scure/bip39", "time-span", "@turf/invariant", "mdast-util-mdx", "randomfill", "@firebase/data-connect", "@csstools/postcss-hwb-function", "protocols", "@storybook/addon-actions", "@dotenvx/dotenvx", "@tiptap/extension-hard-break", "term-size", "gray-matter", "remove-accents", "@csstools/postcss-font-format-keywords", "query-selector-shadow-dom", "@actions/github", "@csstools/postcss-color-function", "esm", "value-equal", "@fastify/fast-json-stringify-compiler", "@internationalized/date", "@rushstack/ts-command-line", "ospath", "@vueuse/metadata", "async-sema", "@tiptap/extension-floating-menu", "@types/history", "eslint-plugin-unicorn", "vue-router", "@jsonjoy.com/fs-snapshot", "truncate-utf8-bytes", "ent", "hast-util-to-estree", "postcss-opacity-percentage", "@vercel/nft", "@changesets/types", "just-extend", "@types/katex", "@algolia/client-analytics", "qrcode-terminal", "protocol-buffers-schema", "node-dir", "caller-callsite", "coa", "@acemir/cssom", "@nestjs/config", "@types/mime-types", "@opentelemetry/instrumentation-restify", "@pnpm/types", "@standard-schema/utils", "react-draggable", "nock", "use-debounce", "@typescript/native-preview-linux-x64", "corser", "@npmcli/move-file", "named-placeholders", "command-line-args", "conventional-changelog-writer", "@prisma/client", "@eslint/compat", "use-composed-ref", "@sentry-internal/tracing", "is-finite", "strip-bom-string", "parse-srcset", "idb-keyval", "@graphql-codegen/typescript", "@tiptap/extension-placeholder", "@sec-ant/readable-stream", "ts-log", "@so-ric/colorspace", "estree-util-to-js", "lazy-ass", "@peculiar/asn1-schema", "utf8-byte-length", "read-package-up", "kysely", "@opentelemetry/instrumentation-cassandra-driver", "read-package-json", "rehype-parse", "@types/d3-quadtree", "lit-html", "@mongodb-js/saslprep", "png-js", "@wry/context", "table-layout", "@opentelemetry/instrumentation-memcached", "@rushstack/terminal", "@csstools/postcss-trigonometric-functions", "discontinuous-range", "clean-regexp", "postcss-clamp", "expo-constants", "rehype-stringify", "@cacheable/utils", "@opentelemetry/resource-detector-container", "@graphql-tools/git-loader", "@algolia/client-personalization", "parse-path", "pretty-hrtime", "base-64", "@next/eslint-plugin-next", "event-stream", "react-window", "hashery", "pause-stream", "@stoplight/types", "use-latest", "command-line-usage", "babel-plugin-transform-flow-enums", "@juggle/resize-observer", "urijs", "markdown-extensions", "@aws-sdk/middleware-websocket", "@tiptap/extension-text", "rollup-plugin-visualizer", "@csstools/postcss-nested-calc", "@opentelemetry/instrumentation-net", "invert-kv", "@expo/cli", "sort-keys-length", "cacheable", "lodash.upperfirst", "universal-github-app-jwt", "lit", "@jsonjoy.com/fs-print", "@csstools/postcss-oklab-function", "rsvp", "@sentry/vercel-edge", "@storybook/icons", "ncp", "tsup", "wordwrapjs", "@swc/jest", "@mapbox/unitbezier", "@types/three", "@react-stately/flags", "es6-promisify", "qified", "@react-spring/shared", "pbf", "lcid", "@opentelemetry/resource-detector-aws", "base64url", "@nuxt/opencollective", "railroad-diagrams", "@react-spring/types", "@expo/package-manager", "colorjs.io", "@react-spring/core", "octokit", "@turbo/linux-64", "mini-svg-data-uri", "@expo/osascript", "path-dirname", "workbox-precaching", "mongodb-connection-string-url", "@expo/metro-config", "yoga-layout", "resolve-protobuf-schema", "ext-list", "stubborn-fs", "byline", "de-indent", "preact-render-to-string", "radix3", "nearley", "@anthropic-ai/claude-agent-sdk", "@cucumber/gherkin", "emojilib", "@nestjs/cli", "estree-util-attach-comments", "jsonschema", "stacktrace-js", "@radix-ui/react-one-time-password-field", "stacktrace-gps", "react-popper", "expo-modules-core", "stylelint-config-standard", "@rspack/binding", "@types/memcached", "rgbcolor", "secure-compare", "@azure/core-xml", "@storybook/addon-viewport", "lottie-web", "@aws-sdk/middleware-eventstream", "@types/web-bluetooth", "node-notifier", "@storybook/addon-controls", "ky", "libmime", "@es-joy/jsdoccomment", "@csstools/postcss-ic-unit", "url-loader", "@opentelemetry/instrumentation-router", "ansicolors", "babel-plugin-dynamic-import-node", "ext-name", "@algolia/recommend", "map-age-cleaner", "parse-url", "@nestjs/swagger", "@mapbox/vector-tile", "@csstools/postcss-text-decoration-shorthand", "react-native-safe-area-context", "tippy.js", "@urql/core", "is-path-in-cwd", "jasmine-core", "@gar/promise-retry", "union", "@babel/plugin-proposal-json-strings", "@xyflow/system", "when-exit", "regexp-tree", "serve-handler", "@contenthook/node", "uniq", "merge-options", "@opentelemetry/instrumentation-aws-lambda", "cron", "node-mock-http", "expo-modules-autolinking", "@react-spring/animated", "@expo/spawn-async", "@types/raf", "@vitest/browser", "git-up", "@volar/typescript", "@storybook/builder-webpack5", "string.prototype.padend", "propagate", "estree-util-build-jsx", "@azure/core-http-compat", "from", "is-ssh", "@angular/core", "contenthook", "hast-util-to-jsx-runtime", "foreach", "lodash.isobject", "postcss-overflow-shorthand", "oxc-resolver", "@oclif/core", "babel-plugin-syntax-trailing-function-commas", "lodash.uniqby", "@jsonjoy.com/fs-node-to-fsa", "expo-font", "section-matter", "@csstools/postcss-unset-value", "lru-queue", "@types/inquirer", "bullmq", "@aws-sdk/middleware-signing", "@graphql-codegen/schema-ast", "@types/through", "browser-assert", "@electron/get", "unicode-emoji-modifier-base", "@types/cookie-parser", "@stripe/react-stripe-js", "@contenthook/browser", "@react-spring/rafz", "mathml-tag-names", "@pnpm/exe", "to-readable-stream", "@types/supercluster", "obliterator", "opentracing", "@react-native/js-polyfills", "@types/hammerjs", "@shikijs/vscode-textmate", "@microsoft/tsdoc-config", "nested-error-stacks", "array-slice", "memoizee", "skin-tone", "@react-native/assets-registry", "@jsonjoy.com/fs-fsa", "postcss-flexbugs-fixes", "css-select-base-adapter", "@storybook/blocks", "rc-util", "@csstools/postcss-stepped-value-functions", "git-url-parse", "@open-draft/deferred-promise", "@babel/plugin-proposal-dynamic-import", "@aws-sdk/util-dynamodb", "@tweenjs/tween.js", "lit-element", "tarn", "metro-resolver", "find-file-up", "@types/webpack", "@types/react-router-dom", "listenercount", "metro-core", "@graphql-codegen/typescript-operations", "dotenv-cli", "algoliasearch", "@sentry/integrations", "js-md4", "meshoptimizer", "@radix-ui/react-use-is-hydrated", "p-each-series", "geojson-vt", "@types/sanitize-html", "@types/react-router", "@redocly/openapi-core", "timers-ext", "check-types", "@jest/environment-jsdom-abstract", "langsmith", "@napi-rs/canvas-linux-x64-musl", "which-pm-runs", "@storybook/react-vite", "find-pkg", "stylelint-scss", "@babel/plugin-proposal-export-namespace-from", "@vue/devtools-kit", "marked-terminal", "@aws-sdk/client-dynamodb", "murmurhash-js", "@oxlint/binding-linux-x64-gnu", "react-test-renderer", "@storybook/addon-highlight", "@graphql-codegen/add", "static-eval", "@opentelemetry/instrumentation-dns", "@hapi/bourne", "promise-polyfill", "relay-runtime", "babel-plugin-react-compiler", "stoppable", "@azure-rest/core-client", "hast-util-sanitize", "@storybook/addon-backgrounds", "@vue/devtools-shared", "pdf-lib", "outdent", "inflection", "@sentry/bundler-plugin-core", "fast-json-parse", "@peculiar/asn1-cms", "@react-navigation/elements", "js-tiktoken", "object.hasown", "@react-native/gradle-plugin", "@firebase/auth", "babel-plugin-transform-react-remove-prop-types", "jsonc-eslint-parser", "json-stringify-pretty-compact", "@sinonjs/text-encoding", "@fastify/proxy-addr", "flush-write-stream", "@csstools/selector-resolve-nested", "fp-ts", "@opencode-ai/sdk", "please-upgrade-node", "@storybook/addon-toolbars", "@storybook/addon-essentials", "is-primitive", "@storybook/addon-measure", "@pnpm/linux-x64", "semver-truncate", "qrcode.react", "i18next-browser-languagedetector", "iterall", "spawn-command", "babel-preset-expo", "lmdb", "@oxc-parser/binding-linux-x64-musl", "default-require-extensions", "@graphql-codegen/core", "mpath", "@storybook/types", "ts-pattern", "@angular/common", "sift", "@octokit/webhooks-methods", "is-root", "hast-util-to-string", "@lit/reactive-element", "osenv", "lib0", "raf-schd", "@aws-sdk/client-ssm", "eslint-plugin-vue", "react-native", "prettier-plugin-tailwindcss", "repeating", "expo-file-system", "@webgpu/types", "flatbuffers", "@types/stylis", "eslint-plugin-es", "tiny-case", "command-exists", "@img/sharp-linux-arm64", "wonka", "uid-safe", "@react-spring/web", "queue-tick", "esm-env", "abitype", "@storybook/react-dom-shim", "babel-plugin-react-native-web", "strip-outer", "node-machine-id", "@tailwindcss/typography", "trim-repeated", "@opentelemetry/resource-detector-azure", "yocto-spinner", "superstruct", "into-stream", "@npmcli/arborist", "mquery", "ts-essentials", "detective-postcss", "@hapi/boom", "@babel/regjsgen", "@storybook/core", "@base44/sdk", "@rushstack/rig-package", "pdf-parse", "expo-keep-awake", "react-native-screens", "react-error-overlay", "@types/testing-library__jest-dom", "@xyflow/react", "@apollo/client", "@tiptap/extension-image", "@react-native/babel-plugin-codegen", "shellwords", "@opentelemetry/instrumentation-cucumber", "signedsource", "@cfworker/json-schema", "string-hash", "xdg-app-paths", "leaflet", "sass-embedded", "parse-conflict-json", "@types/webxr", "safe-json-stringify", "direction", "@tiptap/core", "@react-navigation/routers", "hash-sum", "@types/archiver", "lightningcss-linux-arm64-gnu", "vaul", "request-promise-core", "neotraverse", "gonzales-pe", "@types/react-redux", "@opentelemetry/resource-detector-alibaba-cloud", "@aws-sdk/dynamodb-codec", "just-diff", "@types/koa", "javascript-natural-sort", "redeyed", "@opentelemetry/auto-instrumentations-node", "@aws-sdk/client-bedrock-runtime", "detective-stylus", "@firebase/app-compat", "@storybook/core-webpack", "@cacheable/memory", "@datadog/browser-rum-core", "@graphql-hive/signal", "@vitejs/plugin-basic-ssl", "stream-to-array", "fined", "are-docs-informative", "@storybook/addon-outline", "unplugin-utils", "bcrypt", "ast-module-types", "@rollup/rollup-darwin-x64", "@babel/helper-get-function-arity", "@apidevtools/swagger-parser", "@nuxt/kit", "turbo-linux-64", "browser-resolve", "xss", "postcss-initial", "google-protobuf", "swc-loader", "oauth", "@types/stats.js", "@react-native-async-storage/async-storage", "getos", "rehype-sanitize", "webpack-subresource-integrity", "react-dev-utils", "change-case-all", "rollup-pluginutils", "eslint-plugin-simple-import-sort", "xxhash-wasm", "vite-plugin-svgr", "should", "@emotion/stylis", "@lmdb/lmdb-linux-x64", "@algolia/requester-fetch", "@graphql-codegen/cli", "should-equal", "framer-motion", "stat-mode", "clone-stats", "@storybook/instrumenter", "klaw", "@mui/x-date-pickers", "tlds", "@redis/graph", "@aws-crypto/ie11-detection", "popper.js", "defined", "esbuild-wasm", "@codemirror/lint", "https", "fontfaceobserver", "esast-util-from-estree", "ast-kit", "mdast-util-math", "react-freeze", "npm-run-all", "state-local", "@nx/nx-linux-x64-musl", "path", "@react-navigation/native", "should-format", "@types/offscreencanvas", "@contenthook/cli", "front-matter", "tiny-inflate", "opn", "@algolia/client-query-suggestions", "@wry/trie", "fetch-retry", "micromark-extension-frontmatter", "zone.js", "@stylistic/eslint-plugin", "fs-readdir-recursive", "prosemirror-inputrules", "react-aria", "flagged-respawn", "uvu", "normalize-svg-path", "random-bytes", "buffer-equal", "react-dnd-html5-backend", "@nx/js", "@posthog/types", "string-natural-compare", "@opencode-ai/plugin", "detective-typescript", "firebase", "treeverse", "amdefine", "zen-observable", "growly", "@types/accepts", "@module-federation/runtime", "postcss-media-minmax", "babel-preset-fbjs", "@microsoft/api-extractor-model", "posthog-node", "@types/papaparse", "find-my-way-ts", "@napi-rs/nice", "extract-files", "tmp-promise", "markdown-to-jsx", "recma-build-jsx", "@jimp/utils", "@cloudflare/workers-types", "@firebase/performance", "wait-port", "lodash.isempty", "hast-util-from-dom", "@microsoft/api-extractor", "@expo/env", "num2fraction", "node-source-walk", "react-datepicker", "cardinal", "screenfull", "remove-trailing-spaces", "detective-es6", "@graphql-tools/documents", "precinct", "@keyv/bigmap", "focus-trap", "@expo/fingerprint", "@react-navigation/native-stack", "react-intersection-observer", "@storybook/csf-plugin", "@nestjs/axios", "dockerode", "conf", "platform", "@expo/xcpretty", "@rollup/rollup-win32-x64-gnu", "module-definition", "array-each", "currently-unhandled", "memory-pager", "xstate", "@storybook/addon-links", "mammoth", "easy-table", "bfj", "@azure/storage-blob", "cssfilter", "exec-sh", "@xstate/fsm", "openapi-fetch", "node-libs-browser", "@firebase/ai", "react-colorful", "@ant-design/colors", "unicode-trie", "@axe-core/playwright", "@firebase/functions", "@firebase/analytics", "prosemirror-keymap", "detective-sass", "openapi-typescript-helpers", "@jsonjoy.com/fs-core", "eslint-webpack-plugin", "@firebase/messaging", "react-native-gesture-handler", "@angular/compiler", "@ai-sdk/google", "to-arraybuffer", "loud-rejection", "endent", "eslint-plugin-flowtype", "@storybook/react-docgen-typescript-plugin", "@rollup/rollup-win32-arm64-msvc", "object.defaults", "twilio", "@storybook/node-logger", "@egjs/hammerjs", "parse5-sax-parser", "@types/jsonfile", "quill-delta", "fs-write-stream-atomic", "parse-cache-control", "@octokit/openapi-webhooks-types", "@react-navigation/bottom-tabs", "eslint-plugin-es-x", "opencollective-postinstall", "rehype-recma", "@emotion/css", "parallel-transform", "sorted-array-functions", "ox", "just-diff-apply", "lightningcss-darwin-arm64", "ordered-binary", "react-native-svg", "babylon", "detect-port-alt", "stripe", "react-use-measure", "shadcn", "babel-code-frame", "telejson", "oidc-token-hash", "@firebase/component", "cli-table", "toad-cache", "micromark-extension-directive", "get-amd-module-type", "@expo/code-signing-certificates", "@algolia/ingestion", "acorn-loose", "@monaco-editor/react", "@algolia/monitoring", "node-stream-zip", "@opentelemetry/sdk-node", "webpack-manifest-plugin", "should-util", "rbush", "is-in-ci", "@firebase/webchannel-wrapper", "timed-out", "@storybook/addon-interactions", "swagger2openapi", "detective-scss", "remark-math", "lodash.template", "pidusage", "jotai", "@graphql-codegen/typed-document-node", "parse5-html-rewriting-stream", "drizzle-orm", "is-function", "json-stringify-nice", "react-number-format", "hast-util-from-html-isomorphic", "css", "node-cache", "rehype-katex", "reftools", "recma-jsx", "@firebase/auth-types", "scule", "@apm-js-collab/tracing-hooks", "@octokit/app", "react-helmet-async", "diff-match-patch", "detective-amd", "@opentelemetry/exporter-logs-otlp-proto", "@npmcli/redact", "@tiptap/extension-text-style", "@amplitude/analytics-core", "@storybook/test", "stealthy-require", "@img/sharp-linuxmusl-arm64", "@jsonjoy.com/fs-node-utils", "@firebase/app-check", "promise-call-limit", "@angular-devkit/schematics-cli", "@img/sharp-libvips-linuxmusl-arm64", "@preact/signals-core", "@firebase/functions-types", "lodash.templatesettings", "libqp", "omggif", "@aws-sdk/lib-dynamodb", "docker-modem", "@types/keygrip", "@unrs/resolver-binding-linux-arm64-gnu", "unist-util-generated", "@types/content-disposition", "typedoc", "@firebase/auth-compat", "lightningcss-linux-arm64-musl", "js-sha3", "react-stately", "@firebase/functions-compat", "cyclist", "@opentelemetry/exporter-logs-otlp-grpc", "mississippi", "@wdio/logger", "is-stream-ended", "@googlemaps/js-api-loader", "properties-reader", "@sqltools/formatter", "@module-federation/dts-plugin", "liftoff", "clipanion", "@tiptap/extension-list-keymap", "string-convert", "react-pdf", "turndown", "babel-plugin-styled-components", "@swc/core-linux-arm64-gnu", "node-readfiles", "@langchain/core", "@module-federation/managers", "pkijs", "@use-gesture/react", "typed-assert", "@chromatic-com/storybook", "scuid", "eslint-config-react-app", "@firebase/firestore-types", "pino-http", "@module-federation/enhanced", "@jimp/core", "@aws-sdk/endpoint-cache", "indexes-of", "@octokit/webhooks-types", "@nx/workspace", "@electric-sql/pglite-tools", "lru_map", "@algolia/client-abtesting", "third-party-web", "backo2", "@nrwl/devkit", "should-type", "@jimp/types", "json-with-bigint", "@phenomnomnominal/tsquery", "remark", "meros", "oas-validator", "@img/sharp-darwin-arm64", "bytestreamjs", "@rollup/rollup-android-arm64", "@graphql-codegen/gql-tag-operations", "@firebase/messaging-interop-types", "@expo/sdk-runtime-versions", "generic-names", "@urql/exchange-retry", "@rspack/binding-linux-x64-gnu", "@angular/platform-browser", "lightningcss-win32-x64-msvc", "@oxfmt/binding-linux-x64-gnu", "@rollup/rollup-freebsd-x64", "should-type-adaptors", "update-check", "@storybook/router", "mv", "raw-loader", "@babel/cli", "promise-all-reject-late", "recma-parse", "@vue/compiler-vue2", "@wdio/types", "@tiptap/extension-dropcursor", "mongoose", "is-object", "@algolia/client-insights", "fuzzysort", "docker-compose", "json2mq", "utrie", "@datadog/native-metrics", "ethereum-cryptography", "@rollup/rollup-linux-arm-gnueabihf", "@react-aria/i18n", "locate-character", "oas-resolver", "postcss-scss", "emitter-listener", "oas-linter", "@rollup/rollup-android-arm-eabi", "@module-federation/bridge-react-webpack-plugin", "sass-embedded-linux-x64", "pony-cause", "stream-each", "@opentelemetry/instrumentation-runtime-node", "detective-cjs", "isomorphic-dompurify", "whatwg-url-without-unicode", "@heroicons/react", "valid-url", "eslint-plugin-playwright", "convert-to-spaces", "topojson-client", "weak-lru-cache", "@napi-rs/nice-linux-x64-musl", "@use-gesture/core", "lodash._reinterpolate", "eslint-plugin-cypress", "oas-kit-common", "@firebase/app-check-types", "libbase64", "sane", "formik", "@rollup/rollup-linux-arm-musleabihf", "babel-preset-react-app", "exceljs", "@angular/compiler-cli", "@types/bcryptjs", "@types/readdir-glob", "@rollup/rollup-linux-s390x-gnu", "pptxgenjs", "corepack", "resolve-pathname", "@angular/forms", "mobx-react-lite", "postcss-env-function", "@types/dockerode", "@tokenizer/inflate", "capture-exit", "@module-federation/rspack", "@algolia/abtesting", "@jimp/plugin-resize", "stack-chain", "getopts", "@module-federation/manifest", "estree-util-scope", "@types/which", "@maplibre/maplibre-gl-style-spec", "@npmcli/name-from-folder", "vue-tsc", "@ai-sdk/anthropic", "@types/koa-compose", "@firebase/remote-config", "@babel/helper-explode-assignable-expression", "usehooks-ts", "find-babel-config", "hoopy", "babel-plugin-module-resolver", "@angular/router", "rollup-plugin-terser", "oas-schema-walker", "recma-stringify", "@types/oracledb", "@headlessui/react", "longest", "ylru", "tryer", "encoding-japanese", "@types/css-font-loading-module", "fuzzy", "@rollup/rollup-win32-ia32-msvc", "uri-js-replace", "humanize-duration", "@types/http-assert", "eslint-plugin-import-x", "js-sdsl", "@react-types/button", "json-to-pretty-yaml", "@radix-ui/react-icons", "@types/passport", "mobx", "@module-federation/data-prefetch", "@swc/cli", "@storybook/preset-react-webpack", "web-worker", "vue-component-type-helpers", "deep-object-diff", "@listr2/prompt-adapter-inquirer", "swagger-ui-express", "peberminta", "graphlib", "@datadog/datadog-ci", "@mui/x-internals", "@astrojs/compiler", "@npmcli/metavuln-calculator", "@types/pluralize", "window-size", "@parcel/watcher-linux-arm64-glibc", "abs-svg-path", "testcontainers", "debounce-fn", "make-iterator", "@agentclientprotocol/sdk", "node-schedule", "@apidevtools/openapi-schemas", "hast-util-has-property", "@graphql-tools/url-loader", "@npmcli/query", "callsite", "@types/tapable", "openapi-typescript", "@graphql-codegen/client-preset", "is-url-superb", "dijkstrajs", "@firebase/remote-config-types", "@mui/base", "node-cron", "@sendgrid/mail", "dom-walk", "@sendgrid/client", "discord-api-types", "@module-federation/third-party-dts-extractor", "@peculiar/asn1-pkcs9", "vscode-jsonrpc", "@types/validate-npm-package-name", "@one-ini/wasm", "@img/sharp-win32-x64", "@sendgrid/helpers", "textextensions", "@datadog/native-iast-taint-tracking", "@nuxtjs/opencollective", "its-fine", "parchment", "split-ca", "is-natural-number", "@octokit/oauth-methods", "nanostores", "lodash.ismatch", "ink", "typanion", "write", "figgy-pudding", "@rollup/rollup-linux-riscv64-gnu", "parse-imports-exports", "postcss-modules", "@zip.js/zip.js", "knip", "@datadog/native-appsec", "rtl-css-js", "@types/react-syntax-highlighter", "json-pointer", "objectorarray", "babel-types", "stacktrace-parser", "@react-pdf/fns", "@ant-design/icons", "@firebase/performance-types", "d3-sankey", "code-excerpt", "patch-console", "import-cwd", "ultrahtml", "iferr", "onnxruntime-common", "shallow-equal", "@firebase/remote-config-compat", "db0", "@react-dnd/invariant", "@pinojs/redact", "@apollo/utils.keyvaluecache", "expo-status-bar", "@react-pdf/font", "@types/crypto-js", "crc", "private", "@unrs/resolver-binding-linux-arm64-musl", "gitconfiglocal", "worker-farm", "@module-federation/inject-external-runtime-core-plugin", "object.map", "@tailwindcss/forms", "expo-server", "@schematics/angular", "requirejs", "p-throttle", "@whatwg-node/events", "@fastify/cors", "styleq", "react-toastify", "binaryextensions", "@types/xml2js", "@datadog/wasm-js-rewriter", "@envelop/instrumentation", "@types/compression", "@turf/bbox", "has-own-prop", "css-selector-parser", "@manypkg/get-packages", "@rspack/lite-tapable", "os-name", "timeout-signal", "@electron/notarize", "better-path-resolve", "serve", "@expo/require-utils", "@ngtools/webpack", "cose-base", "@azure/core-auth", "async-exit-hook", "@anthropic-ai/claude-agent-sdk-linux-x64", "git-semver-tags", "@storybook/core-common", "@oxc-resolver/binding-linux-x64-musl", "quote-unquote", "@flmngr/flmngr-server-node-express", "@lezer/javascript", "any-base", "@vercel/blob", "@biomejs/cli-linux-x64-musl", "@types/urijs", "@react-dnd/asap", "@semantic-release/error", "@react-native/debugger-shell", "aws-cdk", "@peculiar/webcrypto", "move-concurrently", "focus-lock", "workbox-webpack-plugin", "@codemirror/theme-one-dark", "@babel/plugin-proposal-class-static-block", "junk", "is-subdir", "walkdir", "quill", "js2xmlparser", "babel-eslint", "@swc-node/register", "react-hot-toast", "@types/mute-stream", "@bundled-es-modules/cookie", "@angular/platform-browser-dynamic", "@rollup/rollup-freebsd-arm64", "pkg-conf", "tcp-port-used", "tiny-async-pool", "async-hook-jl", "@angular/build", "@react-dnd/shallowequal", "is2", "@rollup/plugin-inject", "@react-stately/overlays", "string-template", "run-queue", "modify-values", "@bundled-es-modules/statuses", "decompress-targz", "decompress-tarbz2", "@unrs/resolver-binding-darwin-arm64", "expo-linking", "conventional-changelog-core", "bunyan", "decompress-tar", "unimport", "rfc4648", "react-app-polyfill", "dnd-core", "@datadog/browser-core", "express-session", "@nx/eslint", "@swc-node/sourcemap-support", "@lukeed/uuid", "@types/webpack-sources", "remark-frontmatter", "sumchecker", "pg-numeric", "@whatwg-node/disposablestack", "@types/parse5", "wrangler", "fancy-log", "html-react-parser", "dagre-d3-es", "pinia", "cache-manager", "@storybook/core-server", "@tiptap/suggestion", "@edge-runtime/primitives", "@unrs/resolver-binding-win32-x64-msvc", "@apm-js-collab/code-transformer", "xmlcreate", "html-dom-parser", "optimism", "dependency-tree", "module-lookup-amd", "copy-concurrently", "oxc-transform", "conventional-changelog-preset-loader", "@manypkg/find-root", "uncontrollable", "@aws-sdk/client-cloudwatch-logs", "bmp-js", "debuglog", "@storybook/csf-tools", "@vercel/analytics", "c8", "jsonpath", "babel-plugin-syntax-jsx", "request-promise-native", "react-helmet", "stream-combiner2", "html-to-image", "@webassemblyjs/helper-code-frame", "@webassemblyjs/helper-fsm", "regexp-to-ast", "@react-aria/toolbar", "parse-png", "babel-plugin-transform-typescript-metadata", "react-native-web", "@scure/bip32", "parse-statements", "resolve-dependency-path", "fast-url-parser", "@fortawesome/fontawesome-common-types", "@firebase/database", "rc-slider", "csscolorparser", "ts-declaration-location", "@types/har-format", "postcss-browser-comments", "custom-event", "next-intl", "@prisma/query-plan-executor", "@electron/asar", "z-schema", "@react-types/overlays", "readline-sync", "match-sorter", "dns-equal", "@expo/schema-utils", "@vue/test-utils", "@react-aria/overlays", "@types/webpack-env", "glob-stream", "eslint-config-airbnb", "@react-aria/label", "@types/pbf", "passport-jwt", "plugin-error", "zimmerframe", "@types/jquery", "resolve-workspace-root", "@metamask/utils", "windows-release", "exif-parser", "decompress-unzip", "uid2", "lodash.keys", "super-regex", "filing-cabinet", "pdfkit", "hyperlinker", "@codemirror/language", "@intlify/shared", "@vercel/build-utils", "d3-scale-chromatic", "@simple-git/args-pathspec", "@lezer/css", "js-sha256", "merge", "@webassemblyjs/helper-module-context", "ps-tree", "@react-native-community/cli-tools", "only", "downshift", "react-resizable", "@dual-bundle/import-meta-resolve", "@simple-git/argv-parser", "@js-joda/core", "store2", "react-dnd", "aes-js", "parse-svg-path", "koa-convert", "@wdio/utils", "@react-pdf/layout", "@lit-labs/ssr-dom-shim", "license-webpack-plugin", "@noble/ciphers", "vite-plugin-dts", "@types/passport-strategy", "@react-pdf/render", "app-module-path", "@types/bcrypt", "@walletconnect/utils", "cls-hooked", "cli-color", "find-process", "strong-log-transformer", "decompress", "@angular-devkit/build-angular", "@jimp/plugin-rotate", "javascript-stringify", "@types/canvas-confetti", "rehype", "@jimp/plugin-mask", "@playwright/mcp", "remedial", "@types/emscripten", "@tiptap/extensions", "@prisma/driver-adapter-utils", "constantinople", "function-timeout", "@jimp/plugin-color", "@edge-runtime/vm", "@rollup/rollup-linux-riscv64-musl", "swiper", "sass-embedded-linux-musl-x64", "postcss-normalize", "@angular-devkit/build-webpack", "@csstools/normalize.css", "loglevel-plugin-prefix", "@zeit/schemas", "optimist", "@react-stately/collections", "@aws-sdk/signature-v4", "web-push", "add-stream", "@types/ramda", "sanitize.css", "expo-splash-screen", "babel-plugin-named-asset-import", "bplist-creator", "vinyl-fs", "@jimp/plugin-displace", "xregexp", "@swc/core-linux-arm64-musl", "@solana/codecs-numbers", "lighthouse-stack-packs", "@jimp/plugin-blur", "@cnakazawa/watch", "hyphen", "sass-lookup", "growl", "proggy", "@csstools/postcss-relative-color-syntax", "walk-sync", "@expo/metro-runtime", "react-shallow-renderer", "stylus-lookup", "@redocly/config", "@jimp/plugin-print", "exenv", "@astrojs/internal-helpers", "hot-shots", "internal-ip", "@apollo/utils.usagereporting", "mdast-util-directive", "simple-wcswidth", "parse-latin", "check-disk-space", "@jimp/plugin-contain", "@types/wrap-ansi", "@sindresorhus/slugify", "dfa", "eta", "jstransformer", "console-table-printer", "get-pkg-repo", "react-clientside-effect", "eslint-plugin-node", "tsconfig", "human-id", "@formatjs/intl", "@wry/caches", "@hapi/tlds", "@prisma/client-runtime-utils", "http-link-header", "highlightjs-vue", "@react-pdf/types", "stylelint-config-recommended-scss", "treeify", "@nestjs/schedule", "react-chartjs-2", "@fastify/ajv-compiler", "@aws-sdk/client-kms", "@react-stately/tree", "@react-email/render", "@solana/codecs-core", "utf8", "lockfile", "@vitest/browser-playwright", "unist-util-visit-children", "typeorm", "es-aggregate-error", "@parcel/watcher-win32-x64", "js-md5", "react-property", "mapbox-gl", "grid-index", "@webassemblyjs/wast-parser", "@prisma/studio-core", "sortablejs", "@azure/storage-common", "@vercel/node", "@jimp/plugin-circle", "macos-release", "@react-stately/form", "react-focus-lock", "module-alias", "@types/ejs", "rc-motion", "with", "character-parser", "io-ts", "@oozcitak/util", "karma", "@oclif/plugin-help", "@nestjs/jwt", "lightningcss-darwin-x64", "@marijn/find-cluster-break", "@types/source-list-map", "readdir-scoped-modules", "html-minifier", "bin-version", "@types/cookies", "cache-content-type", "merge-source-map", "builder-util-runtime", "farmhash-modern", "unload", "pug-walk", "@img/sharp-darwin-x64", "@graphql-tools/prisma-loader", "@react-pdf/renderer", "@aws-sdk/protocol-http", "pug-runtime", "bs58check", "@lexical/utils", "unist-util-modify-children", "@nestjs/passport", "@google-cloud/precise-date", "@amplitude/analytics-types", "@react-pdf/textkit", "@csstools/cascade-layer-name-parser", "requirejs-config-file", "@conventional-changelog/git-client", "retext-stringify", "retext-latin", "js-string-escape", "react-use", "hls.js", "eyes", "@react-aria/form", "ethers", "better-auth", "nanoclone", "@react-types/grid", "csp_evaluator", "is-expression", "sync-child-process", "@types/diff", "use-memo-one", "react-native-worklets", "retext-smartypants", "@fastify/static", "pug-lexer", "@segment/analytics-core", "esrap", "@react-stately/tabs", "editions", "sort-object-keys", "@antfu/utils", "@lexical/html", "@tiptap/extension-text-align", "lodash.capitalize", "react-intl", "draco3d", "@walletconnect/sign-client", "@electric-sql/pglite-socket", "env-editor", "@csstools/utilities", "sponge-case", "nlcst-to-string", "@jimp/plugin-fisheye", "@csstools/postcss-color-mix-function", "lodash.mapvalues", "@types/uglify-js", "suspend-react", "@codemirror/state", "dom-serialize", "@module-federation/cli", "expo-web-browser", "@shikijs/transformers", "@react-stately/list", "@sentry/hub", "@internationalized/string", "echarts", "pug-parser", "detective", "git-remote-origin-url", "doctypes", "assert-never", "git-hooks-list", "@vercel/functions", "jsbi", "mailparser", "@expo/config", "fs-exists-sync", "@unrs/resolver-binding-darwin-x64", "robots-parser", "is-gzip", "trim-right", "bin-version-check", "@expo/devtools", "@types/mapbox__point-geometry", "proxy-compare", "@lexical/list", "@isaacs/string-locale-compare", "@react-types/combobox", "error", "is", "@better-auth/core", "react-virtualized-auto-sizer", "fast-memoize", "intersection-observer", "@react-stately/menu", "@lexical/table", "postgres-range", "@parcel/watcher-darwin-arm64", "nano-css", "@ljharb/through", "concat-with-sourcemaps", "image-q", "token-stream", "pug", "@internationalized/message", "mermaid", "esbuild-linux-64", "@angular-eslint/bundled-angular-compiler", "pug-linker", "@electron/osx-sign", "markdown-it-anchor", "@react-types/dialog", "pug-filters", "retry-as-promised", "unist-builder", "@react-types/menu", "clone-buffer", "@types/color-name", "babel-traverse", "@restart/hooks", "lolex", "native-duplexpair", "inspect-with-kind", "@pnpm/error", "@parcel/watcher-linux-arm64-musl", "@lexical/clipboard", "@better-auth/telemetry", "@react-aria/combobox", "@mapbox/whoots-js", "cloneable-readable", "pug-code-gen", "@react-types/datepicker", "parse-bmfont-xml", "warn-once", "@react-aria/dialog", "@lexical/history", "is-valid-glob", "@angular-eslint/eslint-plugin", "@mrleebo/prisma-ast", "css-mediaquery", "@prisma/dev", "@sindresorhus/transliterate", "@react-stately/selection", "vite-plugin-pwa", "@changesets/assemble-release-plan", "vue-i18n", "scslre", "@exodus/bytes", "expo", "@codemirror/autocomplete", "@changesets/parse", "@react-stately/table", "refa", "@types/conventional-commits-parser", "mark.js", "xml-parse-from-string", "react-virtuoso", "dir-compare", "hoek", "kareem", "nprogress", "@lexical/rich-text", "fake-indexeddb", "@react-stately/radio", "@react-aria/live-announcer", "@rushstack/problem-matcher", "@intlify/message-compiler", "@types/strip-json-comments", "unbash", "pug-error", "@react-aria/listbox", "jimp-compact", "@oozcitak/dom", "knex", "tlhunter-sorted-set", "@lexical/overflow", "@types/ua-parser-js", "@types/ssh2-streams", "@auth/core", "@changesets/get-release-plan", "@lexical/selection", "@changesets/cli", "@lexical/markdown", "@prisma/adapter-pg", "@xstate/react", "@react-email/tailwind", "rc-tooltip", "qjobs", "@react-types/radio", "create-next-app", "@react-aria/datepicker", "specificity", "@react-stately/datepicker", "@blazediff/core", "@react-pdf/primitives", "@aws-sdk/client-iam", "@react-aria/selection", "native-promise-only", "file-system-cache", "remark-smartypants", "@changesets/git", "trim-trailing-lines", "@csstools/postcss-logical-viewport-units", "@mistralai/mistralai", "@types/file-saver", "webcrypto-core", "async-listen", "@vue/babel-helper-vue-transform-on", "di", "@react-aria/visually-hidden", "@swc/core-darwin-arm64", "media-engine", "@storybook/addon-onboarding", "@react-email/components", "@csstools/postcss-logical-float-and-clear", "@supabase/node-fetch", "@lexical/link", "@react-email/html", "sequelize", "minipass-json-stream", "conventional-recommended-bump", "@img/sharp-wasm32", "@vue/babel-plugin-jsx", "@react-email/section", "rambda", "@types/strip-bom", "@vitest/eslint-plugin", "@changesets/get-dependents-graph", "@react-email/container", "@rollup/plugin-typescript", "@react-email/img", "@react-email/preview", "graphmatch", "expo-image", "object.omit", "sockjs-client", "pug-strip-comments", "@react-email/link", "sitemap", "@types/jasmine", "@tailwindcss/oxide-linux-arm64-gnu", "expand-range", "watchpack-chokidar2", "@apidevtools/swagger-methods", "redis-commands", "@react-email/heading", "@rollup/rollup-linux-ppc64-gnu", "indexof", "deep-diff", "@react-email/body", "expo-manifests", "wkx", "path-data-parser", "drange", "@react-email/row", "nunjucks", "splaytree", "underscore.string", "timsort", "@fortawesome/fontawesome-svg-core", "flatten", "is-observable", "babel-messages", "prosemirror-history", "@globalart/nestjs-logger", "@react-types/textfield", "now-and-later", "image-ssim", "pug-load", "@lexical/text", "@aws-sdk/service-error-classification", "resolve-global", "@cucumber/cucumber-expressions", "@types/filewriter", "@apollo/usage-reporting-protobuf", "java-properties", "@datadog/browser-logs", "@apollo/utils.sortast", "hexoid", "@img/sharp-linux-arm", "@types/cli-progress", "@react-stately/grid", "d3-voronoi", "webpack-log", "css-color-names", "kafkajs", "uqr", "karma-chrome-launcher", "cssfontparser", "@lexical/plain-text", "@msgpack/msgpack", "@types/readable-stream", "@types/command-line-args", "beasties", "@edge-runtime/format", "@shikijs/primitive", "@npmcli/map-workspaces", "babel-template", "regexp-ast-analysis", "teen_process", "rc-resize-observer", "@lexical/mark", "jspdf-autotable", "@aws-sdk/middleware-sdk-sts", "@expo/prebuild-config", "maath", "@google/generative-ai", "regexparam", "dottie", "@changesets/config", "@dagrejs/graphlib", "@turf/distance", "@react-types/tooltip", "@changesets/apply-release-plan", "gunzip-maybe", "pug-attrs", "eslint-plugin-eslint-comments", "lodash.escape", "@react-types/table", "is-deflate", "gsap", "@lexical/react", "@types/tinycolor2", "@react-types/switch", "@ai-sdk/openai-compatible", "@datadog/sketches-js", "@csstools/postcss-media-queries-aspect-ratio-number-values", "@intlify/core-base", "orderedmap", "react-hotkeys-hook", "load-script", "@aws-sdk/client-ses", "edge-runtime", "retext", "merge-refs", "karma-source-map-support", "js-library-detector", "@sveltejs/acorn-typescript", "@edge-runtime/ponyfill", "@react-types/listbox", "@react-types/select", "@edge-runtime/node-utils", "@react-types/slider", "@octokit/auth-unauthenticated", "yazl", "utif2", "mathjs", "@hapi/address", "@types/react-test-renderer", "acorn-node", "lodash.omit", "zrender", "@rspack/plugin-react-refresh", "@lexical/code", "datadog-metrics", "fastparse", "better-call", "pnp-webpack-plugin", "@react-aria/menu", "crypto-randomuuid", "@react-stately/numberfield", "webrtc-adapter", "@langchain/openai", "@lexical/offset", "@electron/universal", "@rollup/plugin-alias", "@react-types/link", "@react-types/breadcrumbs", "@react-native-community/cli-platform-android", "@rollup/rollup-openharmony-arm64", "tv4", "@hey-api/openapi-ts", "is-hotkey", "mobx-react", "typed-rest-client", "eslint-config-standard", "hast-util-heading-rank", "tsc-alias", "croner", "is-negated-glob", "@csstools/postcss-gradients-interpolation-method", "require-package-name", "@react-aria/link", "lead", "@globalart/nestcord", "browser-or-node", "unist-util-find-after", "stylus", "@csstools/postcss-media-minmax", "speedline-core", "@react-email/button", "@graphql-tools/apollo-engine-loader", "@octokit/plugin-retry", "isomorphic-unfetch", "@napi-rs/nice-linux-x64-gnu", "math-expression-evaluator", "reduce-css-calc", "xml-crypto", "@sentry/minimal", "react-modal", "@turf/clone", "@react-types/numberfield", "@xhmikosr/downloader", "signale", "@apollo/utils.printwithreducedwhitespace", "@rspack/binding-linux-x64-musl", "slide", "array-equal", "read-yaml-file", "@datadog/browser-rum", "@angular-eslint/utils", "rc-menu", "@changesets/pre", "hsl-to-rgb-for-reals", "three-mesh-bvh", "@changesets/read", "sort-package-json", "@react-aria/progress", "@types/better-sqlite3", "@react-aria/grid", "@csstools/postcss-logical-resize", "inline-style-prefixer", "ts-graphviz", "@aws-cdk/asset-node-proxy-agent-v6", "@parcel/watcher-darwin-x64", "@uiw/codemirror-extensions-basic-setup", "@cucumber/html-formatter", "@changesets/changelog-git", "@changesets/write", "bcp-47-match", "apache-arrow", "@aws-sdk/client-sns", "@nicolo-ribaudo/chokidar-2", "@datadog/datadog-ci-base", "@vue/babel-plugin-resolve-type", "@oxc-transform/binding-linux-x64-gnu", "@wdio/repl", "chevrotain-allstar", "react-scripts", "@google-cloud/bigquery", "micro", "@types/styled-components", "fzf", "@globalart/ddd", "@globalart/oxide", "@iarna/toml", "@react-native/metro-babel-transformer", "@apollo/utils.logger", "ts-deepmerge", "@react-types/progress", "babel-walk", "@changesets/errors", "@react-email/code-block", "webdriver", "vite-compatible-readable-stream", "@globalart/nestjs-swagger", "@types/filesystem", "user-home", "globule", "is-resolvable", "@img/sharp-win32-ia32", "@tiptap/extension-mention", "@prisma/engines", "@astrojs/telemetry", "@fortawesome/free-solid-svg-icons", "@types/adm-zip", "@aws-sdk/client-cognito-identity-provider", "@datadog/flagging-core", "@ant-design/icons-svg", "bech32", "@hapi/pinpoint", "@datadog/openfeature-node-server", "@datadog/datadog-ci-plugin-deployment", "@datadog/datadog-ci-plugin-dora", "@datadog/datadog-ci-plugin-gate", "@changesets/logger", "@ionic/utils-stream", "requizzle", "@react-stately/select", "nuqs", "abortcontroller-polyfill", "nocache", "@unrs/resolver-binding-win32-arm64-msvc", "@typescript/vfs", "@nestjs/typeorm", "jss", "react-grid-layout", "@sveltejs/vite-plugin-svelte", "lodash.map", "clone-regexp", "@vercel/python", "vue-template-compiler", "@supabase/ssr", "@react-leaflet/core", "@napi-rs/canvas-linux-x64-gnu", "@types/rimraf", "@trivago/prettier-plugin-sort-imports", "@img/sharp-linux-s390x", "@react-aria/toggle", "stream-to-promise", "errorhandler", "hermes-compiler", "catharsis", "@angular-eslint/eslint-plugin-template", "ts-pnp", "react-leaflet", "sudo-prompt", "tailwind-variants", "tw-animate-css", "flmngr", "@ethereumjs/rlp", "react-native-reanimated", "to-through", "@react-native-community/cli-server-api", "value-or-function", "prettier-plugin-organize-imports", "chroma-js", "@uiw/react-codemirror", "@react-aria/numberfield", "remark-breaks", "@unrs/resolver-binding-linux-arm-musleabihf", "@react-pdf/pdfkit", "sync-message-port", "password-prompt", "@expo/vector-icons", "@astrojs/markdown-remark", "@types/zen-observable", "@mrmlnc/readdir-enhanced", "expo-json-utils", "@vercel/static-build", "yauzl-promise", "@unrs/resolver-binding-freebsd-x64", "lightningcss-freebsd-x64", "object-path", "@aws-cdk/asset-awscli-v1", "structured-headers", "maplibre-gl", "@react-aria/spinbutton", "is-invalid-path", "@aws-sdk/node-http-handler", "rc-collapse", "rc-overflow", "csv-parser", "p-pipe", "react-base16-styling", "heap-js", "@react-navigation/core", "@react-stately/toast", "@unrs/resolver-binding-linux-arm-gnueabihf", "nerf-dart", "@react-aria/switch", "@next/bundle-analyzer", "tldts-icann", "three-stdlib", "vinyl-sourcemap", "xhr", "@rollup/rollup-linux-loong64-gnu", "@react-aria/radio", "flattie", "resolve-options", "camera-controls", "@asyncapi/specs", "lightningcss-win32-arm64-msvc", "@types/events", "node-rsa", "@types/nlcst", "@peculiar/json-schema", "@nx/web", "json-schema-ref-resolver", "rc-tree", "@mapbox/point-geometry", "titleize", "individual", "constructs", "rehype-slug", "react-confetti", "detect-gpu", "@vercel/remix-builder", "@rolldown/binding-linux-arm64-gnu", "stats.js", "@commander-js/extra-typings", "@pnpm/constants", "@types/google-protobuf", "compare-version", "standardwebhooks", "@csstools/postcss-logical-overflow", "unix-dgram", "vercel", "left-pad", "unist-util-remove", "@testing-library/react-hooks", "@react-native-community/cli-types", "@react-email/code-inline", "@types/draco3d", "@types/command-line-usage", "@react-aria/tabs", "@semantic-release/npm", "troika-three-utils", "@angular-eslint/template-parser", "next-intl-swc-plugin-extractor", "@csstools/postcss-scope-pseudo-class", "rc-dropdown", "@tiptap/extension-table-cell", "expo-secure-store", "@types/json-stable-stringify", "ansi-wrap", "troika-worker-utils", "@csstools/postcss-light-dark-function", "@rc-component/trigger", "@react-aria/breadcrumbs", "@aws-sdk/util-hex-encoding", "@tiptap/extension-table-row", "@turf/boolean-point-in-polygon", "randomatic", "@apollo/cache-control-types", "re-resizable", "@globalart/nestjs-grpc", "@types/sarif", "@vercel/gatsby-plugin-vercel-builder", "serve-favicon", "multipipe", "expo-updates-interface", "@tanstack/eslint-plugin-query", "@opentelemetry/propagation-utils", "jest-canvas-mock", "perfect-scrollbar", "is-dotfile", "@apollo/utils.withrequired", "@storybook/addon-vitest", "tween-functions", "@unrs/resolver-binding-linux-riscv64-gnu", "@react-types/checkbox", "@semantic-release/release-notes-generator", "ag-grid-community", "remark-directive", "madge", "gaze", "chrono-node", "@types/codemirror", "@tiptap/extension-table-header", "vscode-nls", "@ionic/utils-subprocess", "react-native-url-polyfill", "lowdb", "moo-color", "d3-collection", "@tailwindcss/oxide-linux-arm64-musl", "hsl-to-hex", "@aws-sdk/is-array-buffer", "web-encoding", "webgl-sdf-generator", "@react-email/text", "typed-function", "time-stamp", "@parcel/watcher-freebsd-x64", "lightningcss-linux-arm-gnueabihf", "@fastify/merge-json-schemas", "vt-pbf", "@mui/x-data-grid", "react-native-webview", "@unrs/resolver-binding-android-arm64", "fs-mkdirp-stream", "canvas-confetti", "estree-util-value-to-estree", "lodash.zip", "rc-virtual-list", "semantic-release", "parse-glob", "peek-stream", "rc-select", "@react-stately/searchfield", "rc-pagination", "@react-aria/dnd", "@react-types/searchfield", "typebox", "launchdarkly-js-client-sdk", "@storybook/addons", "lazy-universal-dotenv", "make-cancellable-promise", "webgl-constants", "eslint-rule-composer", "safe-identifier", "@bytecodealliance/preview2-shim", "bonjour", "@tailwindcss/oxide-darwin-arm64", "@react-native-community/cli", "@types/geojson-vt", "cwd", "@react-stately/dnd", "@unrs/resolver-binding-linux-ppc64-gnu", "css-selector-tokenizer", "@semantic-release/commit-analyzer", "metaviewport-parser", "amqplib", "error-stack-parser-es", "@vscode/l10n", "system-architecture", "write-json-file", "unconfig-core", "filename-regex", "json-schema-to-typescript", "math-random", "@vercel/redwood", "@types/passport-jwt", "@unrs/resolver-binding-linux-s390x-gnu", "packet-reader", "@azure/keyvault-common", "server-destroy", "@expo/sudo-prompt", "@apollo/protobufjs", "rc-cascader", "init-package-json", "eslint-plugin-jsdoc", "msw-storybook-addon", "is-equal-shallow", "@types/micromatch", "@dagrejs/dagre", "@react-aria/gridlist", "@aws-sdk/client-eventbridge", "node-polyfill-webpack-plugin", "@firebase/app-check-interop-types", "multistream", "lodash.assign", "antd", "elegant-spinner", "@types/pdfkit", "request-ip", "@react-native-community/cli-clean", "react-native-is-edge-to-edge", "@stoplight/spectral-runtime", "@unrs/resolver-binding-wasm32-wasi", "@nx/eslint-plugin", "i18next-http-backend", "aws-cdk-lib", "@img/colour", "postcss-sorting", "phin", "@unrs/resolver-binding-win32-ia32-msvc", "vite-plugin-checker", "@mapbox/mapbox-gl-supported", "chance", "@lydell/node-pty-linux-x64", "@lovable.dev/vite-plugin-hmr-gate", "@google-cloud/logging", "queue-lit", "@csstools/postcss-gamut-mapping", "@exodus/schemasafe", "@slack/bolt", "is-posix-bracket", "@mapbox/geojson-rewind", "parse-numeric-range", "@csstools/postcss-initial", "@storybook/docs-tools", "magic-string-ast", "framesync", "secp256k1", "@next/swc-darwin-arm64", "lottie-react", "@stoplight/spectral-formats", "aws-ssl-profiles", "import-from-esm", "openapi-sampler", "listr-verbose-renderer", "hsl-regex", "@parcel/watcher-android-arm64", "@apollo/server-gateway-interface", "jss-plugin-camel-case", "web-tree-sitter", "rc-progress", "@jsep-plugin/ternary", "rc-input-number", "rc-table", "rc-checkbox", "@semantic-release/github", "plur", "@react-pdf/image", "css-box-model", "events-intercept", "@aws-sdk/util-uri-escape", "rc-notification", "jss-plugin-nested", "@types/cross-spawn", "copyfiles", "@react-native-community/cli-doctor", "lodash.topath", "@googlemaps/markerclusterer", "buffer-writer", "next-auth", "@parcel/watcher-linux-arm-glibc", "troika-three-text", "elkjs", "@hutson/parse-repository-url", "chromium-edge-launcher", "app-builder-lib", "@parcel/watcher-win32-ia32", "@asteasolutions/zod-to-openapi", "tedious", "rc-image", "@parcel/watcher-win32-arm64", "@schummar/icu-type-parser", "rc-tree-select", "@unrs/resolver-binding-android-arm-eabi", "@react-aria/meter", "rehackt", "mixin-object", "react-compiler-runtime", "jsondiffpatch", "stylelint-order", "json-stream-stringify", "expo-asset", "capture-stack-trace", "@react-aria/textfield", "@vercel/ruby", "node-plop", "highcharts", "@stoplight/spectral-core", "use-resize-observer", "fast-base64-decode", "jss-plugin-default-unit", "jss-plugin-global", "btoa-lite", "icu-minify", "synchronous-promise", "@cucumber/gherkin-utils", "@react-stately/color", "babel-generator", "@next/swc-win32-x64-msvc", "parse-headers", "@types/turndown", "@anthropic-ai/claude-agent-sdk-linux-x64-musl", "@0no-co/graphql.web", "rc-drawer", "rc-rate", "icss-replace-symbols", "complex.js", "encode-utf8", "@ant-design/cssinjs", "@stoplight/spectral-functions", "stylelint-config-standard-scss", "rc-switch", "@types/lru-cache", "readline", "a-sync-waterfall", "@rolldown/binding-win32-x64-msvc", "juice", "@aws-sdk/smithy-client", "@apollo/server", "@tailwindcss/oxide-win32-x64-msvc", "tree-sitter", "@codemirror/search", "keytar", "detect-browser", "@types/react-window", "app-builder-bin", "validate.io-array", "rc-tabs", "clean-webpack-plugin", "@unrs/resolver-binding-linux-riscv64-musl", "slate", "boom", "launchdarkly-js-sdk-common", "@storybook/addon-themes", "@parcel/watcher-linux-arm-musl", "@react-types/meter", "@storybook/react-webpack5", "expo-application", "dns-txt", "@hono/zod-validator", "rc-textarea", "regex-cache", "which-pm", "async-listener", "meshline", "@oslojs/jwt", "@react-pdf/png-js", "@oxlint/binding-linux-x64-musl", "multicast-dns-service-types", "parse-github-url", "@react-stately/data", "jss-plugin-vendor-prefixer", "@testing-library/react-native", "preferred-pm", "@sentry/replay", "@types/acorn", "fastest-stable-stringify", "app-root-dir", "@stoplight/spectral-parsers", "regex-utilities", "lru.min", "@react-aria/select", "webdriverio", "rx", "@types/ioredis", "react-beautiful-dnd", "is64bit", "component-type", "expo-system-ui", "@aws-sdk/util-buffer-from", "libsodium", "react-copy-to-clipboard", "p-wait-for", "@swc/core-win32-arm64-msvc", "dogapi", "@aws-sdk/querystring-builder", "@aws-sdk/middleware-retry", "@aws-sdk/property-provider", "@cucumber/tag-expressions", "three", "jss-plugin-props-sort", "untyped", "glogg", "@aws-sdk/client-kinesis", "uhyphen", "glsl-noise", "@aws-sdk/abort-controller", "vite-plugin-inspect", "babel-plugin-const-enum", "karma-jasmine", "noms", "load-yaml-file", "http2-client", "@discordjs/voice", "expo-linear-gradient", "typedoc-plugin-markdown", "json-bignum", "aws-sdk-client-mock", "y-protocols", "semifies", "yjs", "rate-limiter-flexible", "nimma", "mocha-junit-reporter", "@hey-api/json-schema-ref-parser", "@img/sharp-libvips-linux-arm64", "@types/es-aggregate-error", "@rollup/rollup-linux-ppc64-musl", "@react-aria/color", "mem-fs-editor", "@tanstack/match-sorter-utils", "rx-lite", "@aws-sdk/shared-ini-file-loader", "first-chunk-stream", "slick", "prism-react-renderer", "glob-base", "@sentry/tracing", "@csstools/postcss-logical-overscroll-behavior", "@turf/centroid", "@antfu/ni", "@types/bluebird", "alphanum-sort", "@datadog/libdatadog", "unhead", "validate.io-function", "spawn-error-forwarder", "babel-plugin-emotion", "@bundled-es-modules/tough-cookie", "@jimp/png", "@poppinss/exception", "node-fetch-h2", "ethereumjs-util", "material-colors", "@vue-macros/common", "css-vendor", "@ionic/utils-fs", "@epic-web/invariant", "sparkles", "@launchdarkly/js-sdk-common", "jss-plugin-rule-value-function", "@aws-sdk/middleware-sdk-ec2", "sql-highlight", "pm2", "steno", "@react-types/calendar", "eslint-plugin-no-only-tests", "@nestjs/terminus", "rc-steps", "p-map-series", "isbot", "webdriver-bidi-protocol", "@react-aria/tree", "@types/lodash.debounce", "@better-auth/mongo-adapter", "lodash.isarray", "@react-aria/landmark", "builder-util", "console.table", "@angular/cli", "rc-mentions", "buffer-more-ints", "tsdown", "@types/jsesc", "@types/picomatch", "await-to-js", "conventional-changelog", "react-promise-suspense", "@turf/area", "uint8arrays", "regexp-match-indices", "@stoplight/json", "@ionic/utils-process", "expo-dev-menu", "mssql", "style-search", "es6-set", "any-observable", "@base2/pretty-print-object", "listr", "libsodium-wrappers", "listr-update-renderer", "@openfeature/server-sdk", "execall", "vue-loader", "@react-aria/separator", "fontace", "chromatic", "@walletconnect/universal-provider", "@stoplight/json-ref-readers", "@types/seedrandom", "require-like", "@langchain/langgraph-sdk", "find-yarn-workspace-root2", "@otplib/core", "@react-aria/searchfield", "lan-network", "linkedom", "@datadog/datadog-api-client", "fbemitter", "is-port-reachable", "@csstools/postcss-exponential-functions", "lefthook", "@react-stately/disclosure", "rc-field-form", "reduce-flatten", "re2", "@develar/schema-utils", "@types/wait-on", "vendors", "sdp-transform", "babel-cli", "babel-preset-es2015", "babel-preset-env", "tslint", "gulp", "node-sass", "coveralls", "babel-preset-react", "eslint-plugin-standard", "rollup-plugin-node-resolve", "istanbul", "rollup-plugin-babel", "@vue/cli-service", "rollup-plugin-commonjs", "@vue/cli-plugin-babel", "grunt", "rollup-plugin-typescript2", "tape", "extract-text-webpack-plugin", "@vue/cli-plugin-eslint", "babel-preset-stage-0", "babel-plugin-transform-runtime", "ava", "standard", "browserify", "eslint-loader", "babel-polyfill", "gh-pages", "@types/hyper-function-component", "enzyme", "rollup-plugin-postcss", "babel-register", "rollup-plugin-peer-deps-external", "babel-plugin-transform-object-rest-spread", "gulp-rename", "cz-conventional-changelog", "babel-preset-stage-2", "tslint-config-prettier", "sinon-chai", "uglifyjs-webpack-plugin", "optimize-css-assets-webpack-plugin", "gulp-uglify", "@ant-design/web3-common", "@ant-design/web3-icons", "grunt-contrib-jshint", "karma-mocha", "commitizen", "babel", "standard-version", "karma-coverage", "codecov", "del-cli", "jshint", "enzyme-adapter-react-16", "@babel/polyfill", "tsdx", "babel-plugin-add-module-exports", "karma-webpack", "babel-plugin-transform-class-properties", "gulp-util", "vuex", "gulp-babel", "rollup-plugin-uglify", "chai-as-promised", "coffee-script", "grunt-contrib-watch", "release-it", "gulp-sourcemaps", "rollup-plugin-dts", "@types/react-native", "@angular/animations", "grunt-contrib-clean", "karma-jasmine-html-reporter", "vue-style-loader", "jsdoc", "@storybook/testing-library", "flow-bin", "codelyzer", "json-loader", "gulp-sass", "karma-phantomjs-launcher", "jasmine", "fs", "element-ui", "karma-sourcemap-loader", "gulp-concat", "pre-commit", "@semantic-release/git", "jasmine-spec-reporter", "rollup-plugin-vue", "eslint-plugin-babel", "protractor", "yeoman-generator", "grunt-contrib-uglify", "babel-preset-stage-3", "size-limit", "eslint-config-standard-react", "eslint-plugin-html", "karma-coverage-istanbul-reporter", "html-loader", "xo", "pretty-quick", "gulp-mocha", "np", "babelify", "babel-plugin-external-helpers", "babel-plugin-import", "karma-firefox-launcher", "@size-limit/preset-small-lib", "friendly-errors-webpack-plugin", "rollup-plugin-replace", "tap", "react-addons-test-utils", "@semantic-release/changelog", "@babel/node", "rollup-plugin-json", "@alifd/next", "figlet", "@angular/http", "ng-packagr", "gulp-eslint", "expect.js", "download-git-repo", "grunt-cli", "gulp-autoprefixer", "babel-plugin-transform-decorators-legacy", "browser-sync", "@material-ui/core", "awesome-typescript-loader", "microbundle", "react-hot-loader", "gulp-typescript", "tap-spec", "babel-plugin-transform-es2015-modules-commonjs", "karma-spec-reporter", "express-validator", "@react-native-community/eslint-config", "run-sequence", "@angular/language-service", "babel-plugin-transform-vue-jsx", "@types/jasminewd2", "cookie-session", "shx", "@vue/eslint-config-prettier", "rollup-plugin-sourcemaps", "eslint-friendly-formatter", "gulp-plumber", "svelte", "commitlint", "eslint-config-airbnb-typescript", "proxyquire", "babel-helper-vue-jsx-merge-props", "karma-mocha-reporter", "@types/cookie-session", "request-promise", "css-split-webpack-plugin", "phantomjs-prebuilt", "conventional-changelog-cli", "jshint-stylish", "eslint-plugin-mocha", "fast-sass-loader", "@alifd/babel-preset-next", "@vue/eslint-config-typescript", "karma-cli", "mysql", "less-plugin-sass2less", "@release-it/conventional-changelog", "acertea", "microbundle-crl", "@types/classnames", "anywhere-dream", "anything-kitchen-pack-tears", "anywhere-leon", "anywhere-dream-term", "anywhere-leon-eth", "anywhere-dream-demo", "anywhere-leonterms", "anywhere-leon-ethers", "anywhere-leon-demo", "anywhere-leon-web3", "actually-web3-win", "anywhere-leon-test", "avoid-web3-plenty", "alphabet-minute", "grunt-contrib-copy", "ask-dropped-each", "art-near-room-catch", "anakjalanan", "aid-guard1", "@vue/cli-plugin-router", "gulp-jshint", "prompt", "grunt-contrib-concat", "load-grunt-tasks", "karma-chai", "postcss-url", "lerna", "@vue/cli-plugin-typescript", "@stencil/core", "mocha-lcov-reporter", "vinyl-source-stream", "attempt-till-declared", "action-winter-carried", "according-he-proper", "rollup-plugin-copy", "actually-plastic-driven", "aid-human-declared", "grunt-contrib-nodeunit", "airplane-thus-web3-breathing", "babel-preset-stage-1", "karma-sinon-chai", "watchify", "anyone-rule-certain", "@storybook/manager-webpack5", "ember-cli", "gulp-replace", "yosay", "@storybook/addon-a11y", "ember-cli-inject-live-reload", "gulp-less", "@types/enzyme", "eslint-config-google", "@vue/eslint-config-standard", "broccoli-asset-rev", "@storybook/addon-knobs", "babel-plugin-transform-react-jsx", "ember-cli-dependency-checker", "babel-preset-latest", "@ethersproject/providers", "@storybook/addon-info", "node-nats-streaming", "web3", "ember-export-application-global", "enzyme-to-json", "postcss-cli", "ember-cli-babel", "gulp-load-plugins", "ember-cli-htmlbars", "@material-ui/icons", "metro-react-native-babel-preset", "parcel-bundler", "normalize.css", "@storybook/preset-create-react-app", "gulp-if", "font-awesome", "gulp-clean", "gulp-clean-css", "grunt-mocha-test", "rollup-plugin-buble", "ts-node-dev", "sqlite3", "tslint-config-standard", "react-native-builder-bob", "@vue/cli-plugin-vuex", "stylus-loader", "benchmark", "@vue/cli-plugin-unit-jest", "ember-cli-uglify", "faker", "ember-disable-prototype-extensions", "rollup-plugin-url", "pod-install", "parcel", "@types/chalk", "discord.js", "gulp-istanbul", "jsdoc-to-markdown", "@svgr/rollup", "@ethersproject/address", "ember-cli-sri", "@types/chai-as-promised", "compression-webpack-plugin", "rollup-plugin-filesize", "react-bootstrap", "npm-check-updates", "vue-jest", "ember-cli-qunit", "along-disease5", "eslint-plugin-json", "atmosphere-repeat-web3-together", "act-mark-sent6", "@rollup/plugin-image", "node-uuid", "electron", "ember-resolver", "loader.js", "ember-cli-htmlbars-inline-precompile", "vuepress", "watch", "ember-load-initializers", "gulp-watch", "@angular/cdk", "replace-in-file", "gulp-postcss", "jade", "uglify-es", "stylelint-config-prettier", "@types/big.js", "eslint-config-standard-with-typescript", "yeoman-assert", "ancient-sun", "available-percent-pride0", "attempt-band-club", "anybody-office-web3-happened", "arrange-protection-round4", "babel-plugin-transform-flow-strip-types", "async-validator", "istanbul-instrumenter-loader", "gulp-header", "eslint-import-resolver-webpack", "jsdom-global", "vue-class-component", "vue-hot-reload-api", "koa-router", "eventsource-polyfill", "phantomjs", "@fortawesome/react-fontawesome", "rollup-plugin-scss", "vinyl-buffer", "babel-preset-minify", "angular", "yeoman-test", "crypto", "@ethersproject/contracts", "babel-plugin-lodash", "@ethersproject/solidity", "@emotion/core", "ember-try", "jscs", "progress-bar-webpack-plugin", "hardhat", "babel-preset-flow", "rollup-plugin-typescript", "tslint-react", "vue-property-decorator", "ant-design-vue", "prettier-eslint", "svelte-check", "babel-plugin-transform-object-assign", "eslint-plugin-markdown", "typings", "documentation", "jest-styled-components", "babel-plugin-component", "mockjs", "chromedriver", "toformat", "nodeunit", "@oclif/command", "babel-plugin-transform-async-to-generator", "bower", "config", "tslint-eslint-rules", "cpx", "@tsconfig/recommended", "vuedraggable", "babel-plugin-syntax-dynamic-import", "rollup-plugin-esbuild", "rollup-plugin-serve", "ember-source", "tap-min", "vue-html-loader", "isparta", "styled-system", "power-assert", "clear", "markdown-it-container", "@oclif/config", "@babel/plugin-proposal-throw-expressions", "rewire", "@angular/material", "rollup-plugin-livereload", "@babel/plugin-external-helpers", "ember-data", "grunt-contrib-connect", "@ethersproject/networks", "dumi", "@storybook/addon-storysource", "shortid", "@istanbuljs/nyc-config-typescript", "jest-extended", "chalk-animation", "@rollup/plugin-url", "gulp-minify-css", "ts-mocha", "element-plus", "@types/shelljs", "tsd", "@nomiclabs/hardhat-ethers", "ember-cli-app-version", "rollup-plugin-delete", "rollup-plugin-eslint", "karma-browserify", "rollup-plugin-node-builtins", "unbuild", "gulp-cssmin", "@webcomponents/webcomponentsjs", "@vitejs/plugin-vue-jsx", "@types/axios", "nsp", "tslint-loader", "travis-deploy-once", "svelte-preprocess", "child_process", "@sveltejs/kit", "yorkie", "@vitest/coverage-c8", "ember-ajax", "babel-plugin-transform-jsbi-to-bigint", "jasmine-node", "@types/puppeteer", "@oclif/dev-cli", "rollup-watch", "install", "typechain", "@angular/platform-server", "ethereum-waffle", "prettier-plugin-svelte", "webpack-stream", "@fortawesome/fontawesome-free", "@antfu/eslint-config", "babel-preset-react-native", "bumpp", "@babel/plugin-proposal-function-sent", "@oclif/test", "tslint-config-airbnb", "ttypescript", "require-dir", "ember-cli-release", "clipboard", "eslint-config-xo", "babel-preset-es2015-rollup", "@babel/plugin-proposal-function-bind", "koa-static", "@types/sinon-chai", "karma-safari-launcher", "postcss-cssnext", "uppercamelcase", "tsickle", "ghooks", "rollup-plugin-css-only", "@openzeppelin/contracts", "validate-commit-msg", "@babel/plugin-proposal-pipeline-operator", "systemjs", "eslint-plugin-security", "ember-cli-eslint", "eslint-config-egg", "time-grunt", "snazzy", "redux-saga", "@stdlib/bench", "koa-bodyparser", "gulp-bump", "cpy-cli", "@vue/component-compiler-utils", "nightwatch", "svg-sprite-loader", "imports-loader", "@storybook/storybook-deployer", "nwb", "grunt-contrib-coffee", "@types/mkdirp", "grunt-karma", "mock-fs", "@babel/plugin-proposal-do-expressions", "@open-wc/testing", "@types/prompts", "nuxt", "gulp-notify", "@ckeditor/ckeditor5-paragraph", "react-color", "gulp-shell", "grunt-browserify", "@typechain/ethers-v5", "arts-dao", "tslint-plugin-prettier", "karma-sauce-launcher", "eslint-plugin-ember", "@ckeditor/ckeditor5-basic-styles", "jest-serializer-vue", "eslint-plugin-react-native", "tsc-watch", "@ckeditor/ckeditor5-theme-lark", "@types/enzyme-adapter-react-16", "grunt-contrib-cssmin", "mqtt", "@storybook/builder-webpack4", "@storybook/manager-webpack4", "redux-logger", "prettier-eslint-cli", "chai-spies", "eslint-config-oclif", "rollup-plugin-svelte", "@ckeditor/ckeditor5-essentials", "jest-fetch-mock", "@types/styled-system", "@types/core-js", "@sveltejs/adapter-auto", "selenium-server", "@ckeditor/ckeditor5-list", "grunt-eslint", "rollup-plugin-cleanup", "eslint-config-custom", "user", "api-chatfb", "@ckeditor/ckeditor5-heading", "api-chatfb-test", "api-chat-fanpage-facebook", "brfs", "auto-changelog", "@commitlint/config-angular", "@ckeditor/ckeditor5-link", "father", "karma-ie-launcher", "xmldom", "esdoc", "babel-plugin-transform-es2015-modules-umd", "@types/chalk-animation", "rollup-plugin-node-globals", "es6-shim", "@capacitor/core", "gulp-filter", "rollup-plugin-sass", "react-docgen-typescript-loader", "solc", "father-build", "eslint-plugin-prefer-arrow", "@ckeditor/ckeditor5-image", "inject-loader", "grunt-release", "@ckeditor/ckeditor5-block-quote", "@types/bn.js", "autod", "@babel/plugin-transform-object-assign", "@material-ui/lab", "grunt-bump", "transliteration", "ember-cli-shims", "vows", "@ckeditor/ckeditor5-table", "eslint-plugin-sonarjs", "sw-precache-webpack-plugin", "ember-source-channel-url", "egg-bin", "@solana/web3.js", "babel-plugin-transform-es2015-destructuring", "@ckeditor/ckeditor5-autoformat", "gulp-connect", "tsc", "@types/figlet", "@web/test-runner", "eslint-plugin-svelte3", "numeral", "grunt-shell", "onchange", "eslint-plugin-compat", "@ckeditor/ckeditor5-dev-utils", "@storybook/addon-postcss", "@uniswap/v2-core", "@types/graphql", "hapi", "@angular-devkit/build-ng-packagr", "gulp-imagemin", "recompose", "@ckeditor/ckeditor5-editor-classic", "hammerjs", "gulp-tslint", "bip39", "ember-maybe-import-regenerator", "i", "@umijs/test", "jimp", "babel-plugin-react-transform", "codeclimate-test-reporter", "vuetify", "dtslint", "@web/dev-server", "eslint-watch", "babel-preset-es2017", "lab", "@types/gulp", "gatsby", "@types/dotenv", "@nomiclabs/hardhat-waffle", "eslint-plugin-tsdoc", "@ckeditor/ckeditor5-paste-from-office", "@ckeditor/ckeditor5-indent", "cp-cli", "solidity-coverage", "@stencil/sass", "gts", "babel-plugin-transform-regenerator", "@ckeditor/ckeditor5-media-embed", "json-templater", "coffeescript", "exports-loader", "@types/commander", "vue-template-es2015-compiler", "@sveltejs/package", "@alib/build-scripts", "qunit", "gulp-size", "esno", "matchdep", "egg", "@types/faker", "@capacitor/android", "prettier-plugin-solidity", "@storybook/preset-scss", "@polymer/polymer", "remark-cli", "karma-sinon", "axios-mock-adapter", "eslint-config-xo-space", "@vue/tsconfig", "@capacitor/ios", "faucet", "egg-ci", "codecov.io", "0x0lobersyko", "thread-loader", "@ckeditor/ckeditor5-dev-webpack-plugin", "@babel/runtime-corejs2", "webpackbar", "selenium-webdriver", "eslint-import-resolver-alias", "in-publish", "flow-copy-source", "react-styleguidist", "websocket", "gulp-debug", "code", "qunit-dom", "semistandard", "karma-babel-preprocessor", "gulp-coveralls", "@vue/eslint-config-airbnb", "publint", "image-webpack-loader", "http", "karma-typescript", "gulp-cli", "pinst", "ember-cli-content-security-policy", "@types/mongodb", "all-contributors-cli", "create-react-class", "eslint-config-oclif-typescript", "ember-cli-ic-ajax", "animate.css", "downlevel-dts", "@rollup/plugin-buble", "precss", "@types/mongoose", "egg-mock", "null-loader", "metalsmith", "open-cli", "download", "vitepress", "fetch-mock", "vant", "rollup-plugin-alias", "prettier-plugin-packagejson", "doctoc", "@ethersproject/abi", "@ember/optional-features", "emotion", "babel-plugin-named-exports-order", "@ckeditor/ckeditor5-typing", "test", "unplugin-vue-components", "react-testing-library", "@storybook/addon-options"] };

// packages/core/data/popular-pypi.json
var popular_pypi_default = { source: "hugovk/top-pypi-packages", generated: "2026-10-01", rows: [["boto3", 2460723068], ["packaging", 1550430820], ["typing-extensions", 1396876439], ["idna", 1339499236], ["urllib3", 1324020131], ["certifi", 1290239262], ["requests", 1208056002], ["charset-normalizer", 1186581556], ["cryptography", 1070154291], ["setuptools", 973493203], ["cffi", 949615436], ["pygments", 931583890], ["pyyaml", 910851659], ["python-dateutil", 904912826], ["six", 894556866], ["pluggy", 877688356], ["botocore", 853428832], ["pydantic", 842605827], ["pycparser", 837756809], ["click", 817239080], ["pydantic-core", 808518099], ["anyio", 803361854], ["numpy", 801552837], ["pytest", 780160913], ["iniconfig", 755640889], ["annotated-types", 724456796], ["h11", 710837874], ["typing-inspection", 695426964], ["attrs", 692326327], ["s3transfer", 645004335], ["aiobotocore", 619208081], ["protobuf", 619205877], ["httpx", 616760679], ["markupsafe", 614567882], ["httpcore", 613832681], ["python-dotenv", 574103823], ["pyjwt", 565103517], ["platformdirs", 563826118], ["fsspec", 563154338], ["pandas", 547072268], ["jinja2", 537719814], ["jmespath", 509823585], ["pathspec", 509699191], ["filelock", 499529209], ["starlette", 494803667], ["uvicorn", 493237088], ["multidict", 472045565], ["jsonschema", 465214053], ["rpds-py", 463583334], ["yarl", 459889343], ["aiohttp", 455690685], ["rich", 453013909], ["tomlkit", 452388345], ["markdown-it-py", 447223541], ["propcache", 442913585], ["referencing", 437380259], ["jsonschema-specifications", 434995553], ["mdurl", 427032274], ["pillow", 425694980], ["opentelemetry-api", 420163396], ["frozenlist", 417051290], ["tqdm", 414684714], ["pip", 413808389], ["googleapis-common-protos", 411562338], ["pyasn1", 409923988], ["aiosignal", 405888741], ["aiohappyeyeballs", 402259241], ["websockets", 398431816], ["annotated-doc", 393702695], ["wrapt", 392118252], ["pytz", 390851551], ["sniffio", 385470884], ["tzdata", 378926726], ["fastapi", 376994924], ["google-auth", 370945246], ["zipp", 370633303], ["greenlet", 369974693], ["importlib-metadata", 366634016], ["pydantic-settings", 359021487], ["wheel", 358856417], ["tenacity", 340257119], ["trove-classifiers", 338202651], ["python-multipart", 337160283], ["pyasn1-modules", 337140708], ["grpcio-status", 335261209], ["pyarrow", 333202119], ["sqlalchemy", 331730354], ["hatchling", 322755460], ["grpcio", 319720146], ["pyparsing", 317258489], ["lxml", 313948323], ["jiter", 312958613], ["regex", 309895354], ["watchfiles", 305158420], ["s3fs", 303500939], ["ruff", 301403135], ["scipy", 300069551], ["soupsieve", 298296051], ["beautifulsoup4", 297089233], ["openai", 293763944], ["google-api-core", 292918585], ["opentelemetry-semantic-conventions", 290407451], ["psutil", 288818629], ["coverage", 287744815], ["openpyxl", 281999200], ["et-xmlfile", 280384112], ["tomli", 274144944], ["distro", 271961467], ["opentelemetry-sdk", 260741459], ["shellingham", 259804682], ["mypy-extensions", 256840717], ["colorama", 250633499], ["proto-plus", 248050929], ["typer", 244867822], ["requests-oauthlib", 243543641], ["virtualenv", 242417588], ["ghapi", 241697184], ["wcwidth", 240279397], ["cachetools", 238908974], ["exceptiongroup", 235389048], ["mcp", 231742949], ["huggingface-hub", 231512030], ["sse-starlette", 231072915], ["truststore", 229569661], ["more-itertools", 227960649], ["dnspython", 227232303], ["oauthlib", 224763452], ["pytest-asyncio", 224135837], ["httpx2", 221941827], ["httpcore2", 221535246], ["distlib", 219467923], ["editables", 219424113], ["opentelemetry-proto", 218499292], ["httptools", 212349802], ["sortedcontainers", 212274453], ["uvloop", 211131340], ["docstring-parser", 210308424], ["psycopg2-binary", 208775354], ["pytest-cov", 205927033], ["redis", 202023598], ["networkx", 199010494], ["opentelemetry-exporter-otlp-proto-common", 198055010], ["defusedxml", 197732296], ["requests-toolbelt", 197433556], ["msgpack", 193313294], ["fonttools", 193015590], ["rsa", 192092657], ["hf-xet", 188604448], ["werkzeug", 188417291], ["scikit-learn", 188102242], ["prompt-toolkit", 185245942], ["mako", 180525582], ["orjson", 180495295], ["alembic", 179484125], ["tiktoken", 179033638], ["pyopenssl", 178454284], ["opentelemetry-exporter-otlp-proto-http", 177587719], ["nodeenv", 177391741], ["threadpoolctl", 175988041], ["isodate", 175572738], ["langchain", 170709405], ["python-discovery", 169930555], ["cloudpickle", 169563261], ["tokenizers", 166389324], ["pynacl", 166088922], ["chardet", 165621246], ["websocket-client", 165548702], ["joblib", 165173331], ["matplotlib", 162125416], ["tzlocal", 160743734], ["email-validator", 160326207], ["gitpython", 159603247], ["azure-core", 159469350], ["mypy", 159257721], ["itsdangerous", 159237779], ["google-cloud-core", 158330167], ["zstandard", 157498843], ["httpx-sse", 156864481], ["kiwisolver", 156347414], ["dill", 155121071], ["ruamel-yaml", 155104920], ["bcrypt", 154218667], ["identify", 153374984], ["tabulate", 153363832], ["opentelemetry-instrumentation", 152677438], ["pre-commit", 151967102], ["smmap", 151854551], ["msal", 151678051], ["cfgv", 151261783], ["google-cloud-storage", 150396319], ["keyring", 150164030], ["h2", 149251852], ["hpack", 148732375], ["anthropic", 147000216], ["langchain-core", 146804123], ["gitdb", 146522631], ["decorator", 146256296], ["hyperframe", 146181423], ["jaraco-classes", 146143725], ["google-cloud-bigquery", 146124567], ["jaraco-functools", 144339330], ["jeepney", 144329011], ["cycler", 142721879], ["secretstorage", 142308895], ["toml", 141669150], ["jaraco-context", 141206936], ["google-crc32c", 140796400], ["contourpy", 139594438], ["google-resumable-media", 139408268], ["docutils", 138969593], ["grpcio-tools", 138194624], ["google-genai", 138178482], ["pytest-xdist", 138001757], ["execnet", 137378458], ["flask", 137153538], ["prometheus-client", 136740194], ["asn1crypto", 135992736], ["backoff", 134029543], ["xxhash", 131960872], ["docker", 131858211], ["psycopg", 130867953], ["deprecated", 130087567], ["sympy", 129580055], ["jsonpointer", 129002954], ["uritemplate", 128937870], ["uv", 128867870], ["blinker", 128153256], ["sentry-sdk", 127925843], ["ptyprocess", 127906821], ["mpmath", 127136633], ["psycopg-binary", 126278635], ["google-api-python-client", 125829294], ["pypdf", 125401529], ["pexpect", 125242636], ["librt", 124732283], ["google-auth-httplib2", 124140681], ["pytest-json-ctrf", 123843340], ["asgiref", 122066775], ["async-timeout", 121800165], ["multiprocess", 121721294], ["aiofiles", 120497022], ["rapidfuzz", 119792814], ["traitlets", 119776056], ["httplib2", 119458683], ["azure-identity", 117540820], ["webencodings", 117020741], ["narwhals", 115851367], ["black", 114824778], ["google-auth-oauthlib", 114594856], ["opentelemetry-util-http", 112498654], ["msal-extensions", 112464480], ["sqlparse", 109847331], ["authlib", 108345022], ["fastjsonschema", 107882736], ["opentelemetry-exporter-otlp-proto-grpc", 107467958], ["jsonpatch", 107113064], ["asyncpg", 106776505], ["paramiko", 106060924], ["executing", 104362406], ["babel", 104044727], ["snowflake-connector-python", 103373898], ["tornado", 100712647], ["ipython", 99765773], ["grpc-google-iam-v1", 99167267], ["gunicorn", 98987407], ["joserfc", 98554608], ["parso", 98114466], ["jedi", 97989340], ["structlog", 97086230], ["azure-storage-blob", 96992087], ["typedload", 96824519], ["asttokens", 96778905], ["pyproject-hooks", 95993552], ["transformers", 95745832], ["playwright", 94993155], ["xmltodict", 94687744], ["python-docx", 94419127], ["matplotlib-inline", 93566737], ["markdown", 93125718], ["pure-eval", 92484838], ["build", 92310595], ["isort", 91223515], ["litellm", 91222162], ["pyzmq", 91138989], ["tinycss2", 91050637], ["xlsxwriter", 90719225], ["pyee", 89987572], ["google-cloud-aiplatform", 89938201], ["stack-data", 89749999], ["poetry-core", 88582125], ["python-json-logger", 87794905], ["awscli", 87666287], ["aioitertools", 87280240], ["watchdog", 87261951], ["marshmallow", 86478826], ["pymupdf", 85271565], ["awswrangler", 85252234], ["brotli", 84886808], ["pytest-mock", 84797917], ["pytest-timeout", 84169411], ["setuptools-scm", 83255788], ["databricks-sdk", 82468306], ["cachecontrol", 82258128], ["nest-asyncio", 81600769], ["debugpy", 80224813], ["cython", 80004940], ["langsmith", 79060995], ["flatbuffers", 78345367], ["griffelib", 78191169], ["ast-serialize", 78021669], ["mcp-types", 77990911], ["jupyter-core", 77312358], ["types-requests", 76707782], ["croniter", 76496382], ["vcs-versioning", 76460594], ["nbformat", 75927939], ["slack-sdk", 75793931], ["lz4", 75441790], ["pymysql", 75415623], ["pyperclip", 74291260], ["kubernetes", 74124375], ["types-pyyaml", 73807874], ["opentelemetry-instrumentation-requests", 73448972], ["pytokens", 73195226], ["safetensors", 72673120], ["sqlglot", 72072167], ["jupyter-client", 71797948], ["cbor2", 71697985], ["uuid-utils", 71576401], ["jsonref", 71056055], ["datasets", 71014697], ["termcolor", 70952032], ["beartype", 70900509], ["onnxruntime", 70379534], ["cyclopts", 69692927], ["pycryptodome", 69586596], ["mccabe", 69325554], ["opentelemetry-instrumentation-fastapi", 68787887], ["reportlab", 68512641], ["xlrd", 68439143], ["mdit-py-plugins", 67678889], ["tomli-w", 67631963], ["py4j", 67482773], ["fastuuid", 67032433], ["pathable", 66794541], ["opentelemetry-instrumentation-asgi", 66776434], ["loguru", 66583032], ["faker", 66527201], ["jsonschema-path", 66490368], ["importlib-resources", 66454843], ["text-unidecode", 66162098], ["pymongo", 66109460], ["types-protobuf", 65849316], ["lark", 65477088], ["semver", 65320035], ["linkify-it-py", 65183239], ["python-slugify", 64889471], ["ruamel-yaml-clib", 64868988], ["wsproto", 64812371], ["typing-inspect", 64550178], ["rich-rst", 63730130], ["psycopg2", 63452431], ["py-key-value-aio", 62986416], ["argon2-cffi-bindings", 61897186], ["requests-file", 61776773], ["torch", 61685076], ["aiosqlite", 61467947], ["graphql-core", 61304175], ["deprecation", 61230814], ["pypdfium2", 61185795], ["invoke", 61109181], ["mistune", 61023306], ["bleach", 60785064], ["scramp", 60638606], ["argon2-cffi", 60622837], ["types-toml", 60394552], ["rfc3339-validator", 60374014], ["arrow", 60223070], ["shapely", 59555741], ["grpclib", 58604526], ["pycodestyle", 58431787], ["smart-open", 57961119], ["caio", 57381244], ["argcomplete", 57360952], ["opentelemetry-exporter-otlp", 57176536], ["comm", 56482832], ["google-cloud-secret-manager", 56326164], ["mmh3", 56071545], ["jsonpath-ng", 55783591], ["ipython-pygments-lexers", 55668185], ["uncalled-for", 55632581], ["textual", 55511408], ["markdownify", 55504175], ["ipykernel", 55498266], ["python-pptx", 55284813], ["toolz", 55176984], ["duckdb", 55118216], ["types-certifi", 54871982], ["aiofile", 54517779], ["fastmcp", 54260270], ["durationpy", 54224638], ["deepdiff", 54107568], ["pendulum", 53541176], ["pdfminer-six", 53512724], ["responses", 53196428], ["polars", 52383366], ["hypothesis", 52357493], ["modal", 52275469], ["numba", 52272647], ["llvmlite", 52183739], ["langchain-protocol", 52109852], ["openapi-pydantic", 51867911], ["synchronicity", 51827100], ["typeguard", 51030609], ["pydantic-extra-types", 50785699], ["nbclient", 50524443], ["installer", 50445424], ["plotly", 50381302], ["dulwich", 50164006], ["zope-interface", 50024324], ["requests-aws4auth", 49992371], ["nbconvert", 49832800], ["msrest", 49753402], ["pygithub", 49636886], ["datadog", 49361475], ["backports-zstd", 49103701], ["tree-sitter", 48510727], ["pyspark", 48293347], ["antlr4-python3-runtime", 48112920], ["fastmcp-slim", 48078807], ["pandocfilters", 47984555], ["humanize", 47964245], ["jupyterlab-pygments", 47790188], ["botocore-stubs", 47667783], ["pyflakes", 47605407], ["pycryptodomex", 47477810], ["opentelemetry-instrumentation-httpx", 47301394], ["pkginfo", 47294248], ["dataclasses-json", 47126835], ["humanfriendly", 47018115], ["cssselect2", 46604472], ["freezegun", 46076017], ["click-plugins", 45868983], ["portalocker", 45826148], ["amqp", 45662090], ["langgraph", 45220874], ["kombu", 45124680], ["py", 44876609], ["polars-runtime-32", 44836456], ["types-s3transfer", 44818554], ["colorlog", 44688968], ["json5", 44326501], ["celery", 43964239], ["pg8000", 43948989], ["thrift", 43881894], ["vine", 43840564], ["billiard", 43709921], ["future", 43597478], ["redshift-connector", 43381142], ["nltk", 43359919], ["langgraph-sdk", 43278883], ["triton", 43061838], ["click-repl", 43022467], ["google-cloud-resource-manager", 42838659], ["django", 42317188], ["simplejson", 42202185], ["click-didyoumean", 42186406], ["langgraph-checkpoint", 42178920], ["ormsgpack", 42145752], ["google-cloud-pubsub", 41944943], ["confluent-kafka", 41861702], ["orderly-set", 41665759], ["rich-toolkit", 41619275], ["absl-py", 41577044], ["poetry", 41555108], ["flask-cors", 41370266], ["langgraph-prebuilt", 41356263], ["types-python-dateutil", 41288063], ["pysocks", 41132996], ["ty", 41094157], ["backports-tarfile", 41016156], ["pyright", 40821877], ["azure-keyvault-secrets", 40771628], ["ecdsa", 40716741], ["pdfplumber", 40659751], ["semantic-version", 40642455], ["prettytable", 40575578], ["flake8", 40486402], ["ijson", 40201001], ["bracex", 40042502], ["bytecode", 39946839], ["fastapi-cli", 39841845], ["crashtest", 39716850], ["ddtrace", 39552130], ["cleo", 39507458], ["opensearch-py", 39360354], ["posthog", 39354443], ["peewee", 39276698], ["wcmatch", 39048173], ["astroid", 38885677], ["pylint", 38815379], ["temporalio", 38792091], ["webcolors", 38712403], ["dateparser", 38641653], ["pytest-rerunfailures", 38542157], ["altair", 38483837], ["mypy-boto3-s3", 38354747], ["langchain-text-splitters", 38278433], ["pymssql", 38116666], ["psycopg-pool", 38058124], ["langchain-openai", 37917068], ["opencv-python-headless", 37736806], ["databricks-sql-connector", 37726699], ["coloredlogs", 37717492], ["libcst", 37702007], ["imageio", 37601587], ["boto3-stubs", 37526316], ["isoduration", 37512384], ["strands-agents", 37227208], ["limits", 37201857], ["envier", 37087134], ["stripe", 37019407], ["moto", 36951014], ["pyarrow-hotfix", 36899678], ["fastcore", 36863007], ["fakeredis", 36635793], ["azure-common", 36466052], ["inflection", 36334068], ["nexus-rpc", 36259608], ["uc-micro-py", 36162640], ["fqdn", 36082461], ["trio", 36079481], ["filetype", 35971685], ["async-lru", 35636170], ["uri-template", 35589171], ["aiohttp-retry", 35190332], ["phonenumbers", 34938258], ["elasticsearch", 34849050], ["opentelemetry-instrumentation-threading", 34837668], ["apscheduler", 34790579], ["tldextract", 34673058], ["types-awscrt", 34638468], ["nh3", 34519824], ["cattrs", 34435902], ["amazon-ion", 34155421], ["pbs-installer", 34048283], ["graphviz", 34009870], ["pyphen", 33756596], ["license-expression", 33654546], ["boolean-py", 33648256], ["setproctitle", 33370668], ["google-cloud-appengine-logging", 33349616], ["cuda-bindings", 33267817], ["rfc3986-validator", 33238983], ["jupyter-server", 33098020], ["curl-cffi", 33081519], ["passlib", 32978408], ["google-cloud-logging", 32754918], ["google-cloud-audit-log", 32533270], ["statsmodels", 32528527], ["weasyprint", 32513789], ["outcome", 32390523], ["send2trash", 32297031], ["widgetsnbextension", 32234539], ["gspread", 32174589], ["cuda-pathfinder", 32115407], ["pyotp", 31854550], ["jupyterlab-widgets", 31840727], ["testcontainers", 31795104], ["python-jose", 31564711], ["findpython", 31537631], ["cyclonedx-python-lib", 31533162], ["ipywidgets", 31517572], ["pgvector", 31424511], ["packageurl-python", 31309510], ["jupyterlab", 31256602], ["cramjam", 31200307], ["pycountry", 31175432], ["unidiff", 31146940], ["zopfli", 31099880], ["google-cloud-firestore", 31085493], ["stevedore", 30978610], ["nest-asyncio2", 30897405], ["fastapi-cloud-cli", 30849353], ["opencv-python", 30776632], ["py-serializable", 30703871], ["entrypoints", 30589808], ["rignore", 30569522], ["fastavro", 30396434], ["xgboost", 30319569], ["terminado", 30297401], ["langchain-google-vertexai", 30291987], ["qrcode", 30226393], ["strenum", 30222897], ["opentelemetry-instrumentation-dbapi", 30157425], ["patsy", 30110314], ["zeep", 30034648], ["claude-agent-sdk", 30034208], ["opentelemetry-instrumentation-sqlalchemy", 29980025], ["msgspec", 29900743], ["json-repair", 29672888], ["notebook", 29618799], ["fastar", 29565308], ["pydyf", 29564872], ["jupyter-events", 29454700], ["mysql-connector-python", 29310972], ["graphql-relay", 29099939], ["aenum", 29026560], ["jupyter-server-terminals", 29026143], ["lazy-object-proxy", 28908289], ["ujson", 28716411], ["jupyterlab-server", 28620984], ["events", 28618745], ["selenium", 28515418], ["av", 28505009], ["overrides", 28480305], ["nvidia-nccl-cu13", 28453813], ["pip-requirements-parser", 28376173], ["hiredis", 28341917], ["nvidia-nccl-cu12", 28296908], ["graphene", 28256233], ["pytest-split", 28251131], ["rfc3987-syntax", 28241269], ["opentelemetry-instrumentation-urllib3", 28147530], ["ml-dtypes", 28132894], ["db-dtypes", 28059208], ["notebook-shim", 28054356], ["types-pytz", 28039407], ["delta-spark", 27998153], ["olefile", 27898965], ["langchain-community", 27882881], ["opentelemetry-instrumentation-django", 27789817], ["omegaconf", 27777118], ["opentelemetry-instrumentation-wsgi", 27741493], ["pyodbc", 27702343], ["seaborn", 27683244], ["holidays", 27568789], ["tinyhtml5", 27519470], ["clickhouse-connect", 27413633], ["gcsfs", 27377977], ["nvidia-cudnn-cu13", 27364345], ["sentencepiece", 27335824], ["pip-api", 27328218], ["opentelemetry-instrumentation-psycopg2", 27144703], ["aioboto3", 27091322], ["jupyter-lsp", 27009608], ["ply", 26946200], ["h5py", 26805515], ["pathvalidate", 26794681], ["python-magic", 26615653], ["pyroaring", 26609023], ["snowballstemmer", 26541509], ["opentelemetry-instrumentation-logging", 26424200], ["appdirs", 26330929], ["unidecode", 26143129], ["pip-audit", 25909831], ["gevent", 25868724], ["mlflow-skinny", 25850354], ["crc32c", 25776401], ["dbt-adapters", 25750876], ["dask", 25670440], ["ordered-set", 25605129], ["lazy-loader", 25555220], ["diskcache", 25526548], ["flit-core", 25467741], ["pybreaker", 25244773], ["nvidia-nvjitlink", 25221609], ["opentelemetry-instrumentation-flask", 25183293], ["mock", 25118175], ["cuda-toolkit", 25081307], ["html5lib", 25047498], ["pytest-runner", 24971092], ["scikit-image", 24967854], ["yamllint", 24939524], ["bandit", 24935372], ["oauth2client", 24875759], ["opentelemetry-instrumentation-urllib", 24867653], ["sqlmodel", 24732484], ["logfire-api", 24723065], ["retry", 24708970], ["dbt-common", 24656452], ["trio-websocket", 24561157], ["snowflake-sqlalchemy", 24556041], ["nvidia-cublas", 24508235], ["djangorestframework", 24473425], ["genai-prices", 24462782], ["cloudpathlib", 24394521], ["diff-cover", 24385915], ["mashumaro", 24264518], ["nvidia-cusparselt-cu13", 24241174], ["tblib", 24216010], ["adal", 24204229], ["pydantic-ai-slim", 24191570], ["nvidia-nvshmem-cu13", 24121698], ["pydantic-graph", 23977223], ["click-option-group", 23953859], ["pyrsistent", 23952487], ["rfc3986", 23945213], ["zope-event", 23862655], ["azure-monitor-opentelemetry-exporter", 23824860], ["nvidia-cuda-nvrtc", 23792286], ["nvidia-cufft", 23701653], ["nvidia-cusolver", 23640143], ["partd", 23612258], ["nvidia-cusparse", 23589015], ["langfuse", 23586906], ["nvidia-cuda-runtime", 23521372], ["types-setuptools", 23520100], ["respx", 23471823], ["bidict", 23457027], ["catalogue", 23441495], ["locket", 23406205], ["nvidia-cuda-cupti", 23295029], ["eval-type-backport", 23217754], ["sentence-transformers", 23130560], ["google-cloud-bigquery-storage", 23121767], ["nvidia-curand", 23101737], ["ninja", 23040445], ["validators", 23024889], ["griffe", 22987561], ["dbt-core", 22977277], ["swebench", 22942741], ["inflect", 22935684], ["azure-mgmt-core", 22889157], ["soundfile", 22872493], ["vcrpy", 22828777], ["nvidia-cufile", 22820660], ["pytimeparse", 22812777], ["pytest-metadata", 22804856], ["boltons", 22796997], ["google-cloud-monitoring", 22692763], ["nvidia-nvtx", 22653552], ["realtime", 22455994], ["postgrest", 22445346], ["storage3", 22398109], ["supabase", 22383085], ["retrying", 22341020], ["strictyaml", 22258257], ["opentelemetry-instrumentation-aiohttp-client", 22226052], ["parsedatetime", 22116331], ["agent-client-protocol", 21989041], ["simple-websocket", 21984152], ["lupa", 21893761], ["python-engineio", 21782417], ["spacy", 21727609], ["python-socketio", 21641647], ["requirements-parser", 21593634], ["aws-cdk-asset-awscli-v1", 21570257], ["slowapi", 21511827], ["questionary", 21502838], ["docopt", 21437379], ["murmurhash", 21329157], ["mergedeep", 21302868], ["thinc", 21295279], ["grimp", 21176947], ["pytest-django", 21111730], ["glom", 21067039], ["pyproj", 21048544], ["blis", 21038598], ["face", 21036480], ["einops", 21018794], ["azure-storage-file-datalake", 20956024], ["srsly", 20888662], ["factory-boy", 20850986], ["mlflow", 20849476], ["universal-pathlib", 20817183], ["preshed", 20801914], ["python-http-client", 20780393], ["elastic-transport", 20767558], ["cymem", 20743759], ["requests-mock", 20693557], ["wasabi", 20658472], ["dacite", 20645138], ["awscrt", 20612594], ["azure-storage-queue", 20432299], ["hvac", 20419255], ["py-spy", 20409121], ["hyperlink", 20385659], ["pytest-env", 20350704], ["pybind11", 20271877], ["import-linter", 20268145], ["agate", 20243126], ["sendgrid", 20186874], ["simple-salesforce", 20164989], ["opentelemetry-instrumentation-redis", 20133550], ["supabase-auth", 20056933], ["supabase-functions", 20008875], ["cached-property", 19982767], ["streamlit", 19976582], ["pyiceberg", 19899360], ["python-utils", 19896118], ["confection", 19872149], ["twilio", 19816266], ["schema", 19814154], ["time-machine", 19811394], ["spacy-legacy", 19806203], ["ua-parser", 19786246], ["spacy-loggers", 19781036], ["imagesize", 19535573], ["cssselect", 19509023], ["pytest-httpx", 19498363], ["sqlalchemy-utils", 19484877], ["progressbar2", 19455527], ["py-partiql-parser", 19449562], ["great-expectations", 19439047], ["socksio", 19398725], ["leather", 19379401], ["weasel", 19327432], ["django-cors-headers", 19141380], ["datadog-api-client", 19136605], ["grpcio-health-checking", 19037066], ["texttable", 19011944], ["dbt-extractor", 19003772], ["gql", 18960481], ["semgrep", 18946453], ["lightgbm", 18929207], ["pymdown-extensions", 18918232], ["yfinance", 18899199], ["google-pasta", 18748854], ["tifffile", 18723301], ["google-re2", 18541469], ["pandas-stubs", 18472377], ["sphinx", 18402732], ["id", 18401901], ["oracledb", 18388545], ["pydeck", 18378253], ["jupyter-builder", 18290660], ["pandas-gbq", 18182176], ["pydub", 18172747], ["accelerate", 18160913], ["jira", 18125015], ["readme-renderer", 18107065], ["langchain-anthropic", 18106051], ["types-urllib3", 18062777], ["emoji", 18006700], ["pybase64", 17983744], ["aws-requests-auth", 17980818], ["fire", 17963395], ["flask-login", 17856733], ["opentelemetry-exporter-prometheus", 17824837], ["twine", 17823350], ["pillow-heif", 17803942], ["cron-descriptor", 17657246], ["maxminddb", 17540745], ["openapi-schema-validator", 17426925], ["fastspec", 17352430], ["jsonconversion", 17317184], ["oscrypto", 17296207], ["configargparse", 17294598], ["pbr", 17253397], ["mistralai", 17248165], ["feedparser", 17235228], ["openapi-spec-validator", 17208667], ["alabaster", 17165710], ["tensorboard", 17159286], ["nodejs-wheel-binaries", 17148394], ["rich-click", 17144614], ["lxml-html-clean", 17139110], ["kafka-python", 17085526], ["daff", 17071643], ["pytesseract", 16963455], ["fpdf2", 16949655], ["frozendict", 16947731], ["magika", 16944664], ["shortuuid", 16899100], ["mammoth", 16867197], ["ua-parser-builtins", 16836817], ["sphinxcontrib-serializinghtml", 16826733], ["pdf2image", 16813198], ["py-cpuinfo", 16751853], ["pydot", 16744815], ["dbt-protos", 16680156], ["service-identity", 16679851], ["groq", 16664127], ["pydata-google-auth", 16656505], ["types-cachetools", 16619289], ["sphinxcontrib-htmlhelp", 16581321], ["sphinxcontrib-applehelp", 16572735], ["sphinxcontrib-qthelp", 16571184], ["sphinxcontrib-devhelp", 16558806], ["cobble", 16549342], ["sagemaker", 16499047], ["mysqlclient", 16428646], ["bs4", 16421312], ["prek", 16305299], ["jwcrypto", 16302966], ["torchvision", 16297237], ["maturin", 16275292], ["azure-keyvault-keys", 16249954], ["sounddevice", 16216037], ["sphinxcontrib-jsmath", 16202300], ["snowplow-tracker", 16190076], ["poetry-plugin-export", 16174812], ["google-cloud-spanner", 16123274], ["azure-servicebus", 16100426], ["papermill", 16051131], ["typer-slim", 16048478], ["markitdown", 15992234], ["types-redis", 15967490], ["opt-einsum", 15965143], ["natsort", 15958252], ["immutabledict", 15927821], ["bitarray", 15829473], ["sshtunnel", 15822070], ["levenshtein", 15821343], ["tld", 15764825], ["youtube-transcript-api", 15720714], ["multitasking", 15714484], ["databricks-labs-blueprint", 15702781], ["watchtower", 15681038], ["optuna", 15657252], ["google-cloud-speech", 15596284], ["swifter", 15591113], ["types-cffi", 15564267], ["mlflow-tracing", 15557879], ["jsonpath-python", 15519351], ["tree-sitter-languages", 15497466], ["pypdf2", 15485786], ["uv-build", 15481417], ["gremlinpython", 15434058], ["nvidia-cudnn-cu12", 15421135], ["types-paramiko", 15391873], ["genson", 15291561], ["nvidia-cublas-cu12", 15265459], ["rich-argparse", 15240610], ["firebase-admin", 15211488], ["msrestazure", 15059324], ["trino", 15053380], ["lockfile", 15040945], ["pywavelets", 15024688], ["vulture", 15012861], ["grpc-interceptor", 15010854], ["google-cloud-kms", 15009184], ["google-cloud-bigtable", 14862819], ["pyathena", 14819922], ["puremagic", 14818837], ["pytest-randomly", 14751548], ["parse", 14672816], ["deptry", 14619634], ["google-cloud-tasks", 14596026], ["opentelemetry-distro", 14578539], ["pfzy", 14577574], ["nvidia-cuda-nvrtc-cu12", 14568825], ["ldap3", 14560546], ["blake3", 14560205], ["pyspnego", 14552017], ["whitenoise", 14544498], ["langchain-classic", 14536643], ["jsonpickle", 14507452], ["tox", 14478227], ["imageio-ffmpeg", 14465558], ["hatch-vcs", 14446015], ["oss2", 14420663], ["ratelimit", 14412528], ["nvidia-cusparse-cu12", 14390811], ["inquirerpy", 14387640], ["ansicolors", 14386963], ["dunamai", 14379703], ["nvidia-cusolver-cu12", 14354022], ["nvidia-cufft-cu12", 14350810], ["wandb", 14331469], ["dask-expr", 14311199], ["opentelemetry-semantic-conventions-ai", 14302787], ["ipdb", 14250819], ["nvidia-cuda-runtime-cu12", 14243563], ["opentelemetry-resourcedetector-gcp", 14240092], ["ftfy", 14219264], ["h3", 14217457], ["pycares", 14211706], ["basedpyright", 14151532], ["nvidia-nvjitlink-cu12", 14137290], ["aiodns", 14117828], ["aws-xray-sdk", 14096058], ["django-filter", 14086521], ["aws-lambda-powertools", 14080187], ["datamodel-code-generator", 14072956], ["pytest-html", 14050038], ["jpype1", 14017332], ["incremental", 14004600], ["nvidia-curand-cu12", 13987433], ["nvidia-ml-py", 13972164], ["pathlib-abc", 13946917], ["nvidia-cuda-cupti-cu12", 13910224], ["jsonlines", 13905554], ["apache-airflow-providers-common-sql", 13869629], ["types-pyopenssl", 13859210], ["pywin32", 13816269], ["resolvelib", 13788291], ["langcodes", 13773742], ["makefun", 13753807], ["google-ads", 13737650], ["cchardet", 13721530], ["skops", 13678429], ["azure-cosmos", 13670963], ["twisted", 13643529], ["langchain-google-genai", 13623730], ["huey", 13609445], ["html2text", 13585266], ["geopandas", 13584164], ["opentelemetry-instrumentation-grpc", 13564477], ["aiokafka", 13505606], ["mkdocs", 13500226], ["rdflib", 13494098], ["google-cloud-run", 13465716], ["hydra-core", 13461437], ["ghp-import", 13451181], ["tree-sitter-bash", 13404115], ["ray", 13378597], ["python-gnupg", 13373380], ["parameterized", 13366268], ["binaryornot", 13330122], ["pyyaml-env-tag", 13312902], ["logfire", 13303236], ["nvidia-nvtx-cu12", 13277758], ["constantly", 13219046], ["automat", 13179061], ["flask-sqlalchemy", 13109494], ["django-extensions", 13107538], ["onnx", 13097633], ["dbt-semantic-interfaces", 13068640], ["cairosvg", 13032505], ["giturlparse", 13014717], ["jupyter-console", 13008486], ["drf-spectacular", 13006705], ["azure-batch", 13001311], ["pyogrio", 12928351], ["ollama", 12926159], ["pooch", 12920868], ["htmldate", 12920574], ["python-snappy", 12915072], ["dockerfile-parse", 12894532], ["pox", 12854141], ["pyrfc3339", 12849314], ["geoip2", 12816263], ["keyrings-google-artifactregistry-auth", 12804785], ["jupyter", 12783659], ["mkdocs-get-deps", 12772406], ["courlan", 12734568], ["trafilatura", 12713883], ["kubernetes-asyncio", 12708389], ["cairocffi", 12701637], ["cfn-lint", 12688969], ["yt-dlp", 12687900], ["tree-sitter-javascript", 12678342], ["opencensus-context", 12665831], ["opencensus", 12643033], ["cmake", 12620030], ["argparse", 12599686], ["ansible-core", 12594950], ["openai-agents", 12593754], ["types-deprecated", 12589108], ["pydeequ", 12576279], ["detect-installer", 12573959], ["pathos", 12571885], ["gcloud-aio-auth", 12571631], ["google-cloud-dataproc", 12545403], ["msoffcrypto-tool", 12519262], ["neo4j", 12493106], ["gast", 12490320], ["ppft", 12488123], ["prometheus-fastapi-instrumentator", 12483557], ["pyserial", 12476930], ["azure-mgmt-resource", 12444524], ["avro", 12427438], ["aiosmtplib", 12384093], ["pip-tools", 12382739], ["patchelf", 12367238], ["faiss-cpu", 12303691], ["tensorboard-data-server", 12297262], ["django-storages", 12258617], ["slack-bolt", 12152513], ["mkdocs-material", 12117393], ["types-jsonschema", 12108521], ["gcloud-aio-storage", 12091313], ["google-cloud-vision", 12061685], ["fasttransport", 12058798], ["griffecli", 12054108], ["readchar", 12050064], ["smdebug-rulesconfig", 12049760], ["opensearch-protobufs", 11992774], ["pysftp", 11990233], ["python-gitlab", 11988954], ["django-stubs-ext", 11988691], ["keras", 11986555], ["qdrant-client", 11978802], ["tensorflow", 11955333], ["snowflake-snowpark-python", 11935093], ["astor", 11928273], ["ctranslate2", 11816014], ["python-daemon", 11788679], ["opentelemetry-instrumentation-botocore", 11688378], ["numexpr", 11658408], ["polyfactory", 11638365], ["syrupy", 11632508], ["pytest-repeat", 11621047], ["asyncssh", 11616817], ["mkdocs-material-extensions", 11597659], ["nvidia-cusparselt-cu12", 11587332], ["sseclient-py", 11580438], ["kestra", 11573001], ["torchmetrics", 11500681], ["paginate", 11421693], ["meson", 11416028], ["chevron", 11410414], ["google-cloud-compute", 11388839], ["fuzzywuzzy", 11379228], ["justext", 11335196], ["line-bot-sdk", 11314880], ["azure-ai-documentintelligence", 11298336], ["cachebox", 11282057], ["types-aiofiles", 11276617], ["obstore", 11211169], ["memray", 11210695], ["opentelemetry-propagator-aws-xray", 11168454], ["types-markdown", 11159812], ["a2a-sdk", 11136777], ["lightning-utilities", 11105548], ["uuid6", 11103597], ["pika", 11102116], ["httpx-ws", 11073610], ["toposort", 11072982], ["clickhouse-driver", 10985589], ["pyinstaller", 10979725], ["office365-rest-python-client", 10977562], ["mypy-boto3-sqs", 10966904], ["opentelemetry-resource-detector-azure", 10963597], ["kfp", 10940202], ["geventhttpclient", 10930930], ["pyproject-api", 10927380], ["formulaic", 10906910], ["wtforms", 10903747], ["interface-meta", 10884149], ["google-cloud-dataplex", 10879555], ["langchain-google-community", 10870860], ["aiomysql", 10851565], ["uuid7", 10838432], ["resend", 10825921], ["pyelftools", 10813107], ["azure-core-tracing-opentelemetry", 10788531], ["backrefs", 10725763], ["pyinstaller-hooks-contrib", 10711190], ["fasteners", 10682089], ["django-stubs", 10681757], ["granian", 10654974], ["azure-monitor-opentelemetry", 10631019], ["timm", 10621757], ["cohere", 10601912], ["rouge-score", 10584876], ["geopy", 10573552], ["azure-data-tables", 10564541], ["google-cloud-dlp", 10563329], ["jaydebeapi", 10559450], ["django-redis", 10537415], ["mini-swe-agent", 10533281], ["userpath", 10528864], ["geographiclib", 10486779], ["pytorch-lightning", 10457624], ["xarray", 10439978], ["google-cloud-storage-control", 10408708], ["launchdarkly-eventsource", 10398017], ["types-croniter", 10389500], ["sqlalchemy-bigquery", 10380530], ["uv-dynamic-versioning", 10376506], ["pkgutil-resolve-name", 10337489], ["pyroscope-io", 10297104], ["google-adk", 10279198], ["datetime", 10261369], ["sqlalchemy-spanner", 10259463], ["pytest-benchmark", 10252804], ["pytzdata", 10232230], ["pyinstrument", 10161795], ["python-ulid", 10149289], ["weaviate-client", 10126725], ["langdetect", 10114616], ["monotonic", 10098818], ["pydocket", 10086873], ["soxr", 10082805], ["pipenv", 10023668], ["flask-wtf", 10001845], ["pytest-socket", 9991602], ["google-cloud-translate", 9979714], ["expiringdict", 9974275], ["tavily-python", 9958753], ["python-frontmatter", 9956281], ["mypy-boto3-dynamodb", 9951587], ["fastparquet", 9945618], ["pikepdf", 9943889], ["aiohttp-cors", 9921184], ["locust", 9854386], ["pytest-base-url", 9845565], ["altgraph", 9832902], ["pytest-json-report", 9805355], ["launchdarkly-server-sdk", 9803497], ["azure-datalake-store", 9801648], ["google-cloud-texttospeech", 9798661], ["types-boto3", 9798565], ["uritools", 9784950], ["python-levenshtein", 9762641], ["contextlib2", 9740707], ["azure-storage-file-share", 9725139], ["aiolimiter", 9722997], ["cronsim", 9699377], ["types-aiobotocore-s3", 9664552], ["simpleeval", 9661318], ["types-aiobotocore", 9623659], ["user-agents", 9599175], ["junitparser", 9585271], ["types-tabulate", 9580086], ["sqlfluff", 9564388], ["opentelemetry-instrumentation-celery", 9522665], ["azure-mgmt-storage", 9519935], ["iso8601", 9505713], ["rq", 9478256], ["statsd", 9467553], ["pyclipper", 9440611], ["deltalake", 9437809], ["elevenlabs", 9421181], ["pycrypto", 9420356], ["opentelemetry-instrumentation-asyncpg", 9369696], ["scp", 9353304], ["mypy-boto3-lambda", 9296939], ["colorful", 9281531], ["netaddr", 9278796], ["pymupdf4llm", 9226038], ["pytest-playwright", 9212025], ["minio", 9192007], ["azure-keyvault-certificates", 9191781], ["opentelemetry-instrumentation-system-metrics", 9183090], ["daytona-api-client-async", 9137901], ["faster-whisper", 9117958], ["azure-mgmt-compute", 9110843], ["daytona-toolbox-api-client-async", 9110524], ["daytona-api-client", 9106643], ["tree-sitter-c", 9095281], ["databricks-cli", 9085920], ["protobuf3-to-dict", 9073922], ["asyncio", 9063518], ["daytona-toolbox-api-client", 9060308], ["tree-sitter-python", 9060253], ["xmlsec", 9058699], ["meson-python", 9051176], ["shap", 8991052], ["trimesh", 8981551], ["primp", 8976568], ["jellyfish", 8916499], ["speechrecognition", 8904583], ["asgi-lifespan", 8865776], ["pickleshare", 8850914], ["google-cloud-language", 8838628], ["rank-bm25", 8825453], ["adlfs", 8790629], ["icalendar", 8763200], ["looker-sdk", 8762573], ["tree-sitter-typescript", 8748145], ["google-cloud-container", 8733936], ["pyxlsb", 8731774], ["daytona", 8691227], ["google-cloud-trace", 8685733], ["slicer", 8680585], ["roman-numerals", 8679033], ["pyppmd", 8676028], ["py7zr", 8652399], ["tritonclient", 8619750], ["pybcj", 8617566], ["jax", 8617018], ["django-debug-toolbar", 8612233], ["instructor", 8611268], ["openinference-semantic-conventions", 8603965], ["librosa", 8590479], ["google-cloud-build", 8588970], ["inflate64", 8585133], ["google-cloud-videointelligence", 8567014], ["blessed", 8565879], ["screeninfo", 8534938], ["svix", 8533455], ["azure-eventhub", 8531467], ["pyproject-metadata", 8518708], ["pandera", 8502383], ["tree-sitter-java", 8496600], ["multivolumefile", 8477158], ["opentelemetry-exporter-gcp-trace", 8472998], ["pypika", 8459067], ["astunparse", 8447574], ["peft", 8417278], ["python-bidi", 8412760], ["jaxlib", 8409796], ["dagster-pipes", 8405863], ["junit-xml", 8392715], ["flask-limiter", 8357145], ["nvidia-cufile-cu12", 8348079], ["kaleido", 8342210], ["dpath", 8338406], ["google-ai-generativelanguage", 8332965], ["apache-airflow-providers-snowflake", 8330396], ["pgpy", 8320544], ["backcall", 8319741], ["microsoft-kiota-http", 8308168], ["flower", 8305483], ["colorclass", 8299696], ["langgraph-checkpoint-postgres", 8291358], ["dependency-injector", 8288432], ["mypy-boto3-rds", 8277359], ["marshmallow-enum", 8275871], ["microsoft-kiota-authentication-azure", 8274068], ["opencv-contrib-python", 8260828], ["azure-kusto-data", 8260438], ["cdp-use", 8249960], ["motor", 8233781], ["thefuzz", 8226728], ["microsoft-kiota-abstractions", 8226173], ["google-cloud-bigquery-datatransfer", 8215886], ["mypy-boto3-cloudformation", 8213852], ["types-pymysql", 8202005], ["openinference-instrumentation", 8196251], ["autobahn", 8193650], ["pydantic-evals", 8186376], ["django-timezone-field", 8183007], ["dagster", 8172493], ["agent-detector", 8163690], ["tree-sitter-c-sharp", 8161215], ["apprise", 8158294], ["txaio", 8152295], ["crcmod", 8122858], ["osqp", 8118895], ["rtree", 8107996], ["aliyun-trace", 8105378], ["aliyun-semantic-conventions", 8105124], ["atlassian-python-api", 8084880], ["python-hcl2", 8078301], ["azure-monitor-query", 8061576], ["sgmllib3k", 8050171], ["cssutils", 8040763], ["tree-sitter-go", 8033670], ["lancedb", 8030713], ["python-crontab", 8004288], ["cachelib", 7987701], ["configparser", 7987515], ["pyrefly", 7977606], ["detect-secrets", 7972264], ["c7n-org", 7970238], ["google-cloud-dataform", 7954786], ["libclang", 7951734], ["langchain-aws", 7951656], ["opentelemetry-exporter-otlp-common", 7915963], ["num2words", 7914003], ["bashlex", 7909684], ["tree-sitter-rust", 7903095], ["google-cloud-workflows", 7902682], ["ffmpeg-python", 7901687], ["ansible", 7901653], ["scikit-build-core", 7891570], ["paho-mqtt", 7847161], ["browser-use", 7827484], ["pygtrie", 7820029], ["dagster-shared", 7802150], ["amplitude-analytics", 7793845], ["microsoft-kiota-serialization-text", 7793799], ["microsoft-kiota-serialization-json", 7791977], ["mypy-boto3-ec2", 7788976], ["mypy-boto3-secretsmanager", 7777252], ["msgraph-core", 7764149], ["xlwt", 7756205], ["gcloud-aio-bigquery", 7728021], ["zstd", 7726838], ["dotenv", 7695213], ["google-cloud-datacatalog", 7685745], ["google-cloud-redis", 7677980], ["azure-mgmt-cosmosdb", 7640268], ["easygui", 7621037], ["pep517", 7606872], ["atpublic", 7597088], ["gepa", 7596521], ["pyrate-limiter", 7593061], ["fabric", 7566472], ["oletools", 7555044], ["burner-redis", 7554562], ["std-uritemplate", 7550409], ["azure-ai-projects", 7544041], ["types-psutil", 7538869], ["google-cloud-storage-transfer", 7533772], ["striprtf", 7510741], ["pcodedmp", 7508750], ["apache-airflow", 7498163], ["bazel-runfiles", 7484486], ["coolname", 7483688], ["bubus", 7453900], ["asyncer", 7446442], ["browser-use-sdk", 7444317], ["bottleneck", 7438801], ["sentinels", 7426833], ["google-generativeai", 7424773], ["elementpath", 7411537], ["dj-database-url", 7411459], ["supervisor", 7403291], ["feedparser-sgmllib", 7399593], ["apache-airflow-providers-mysql", 7325945], ["uvicorn-worker", 7320006], ["pyzipper", 7300437], ["cloudevents", 7280756], ["jsondiff", 7270937], ["aws-sam-translator", 7264288], ["bottle", 7256921], ["pydash", 7250988], ["pywebpush", 7244938], ["smbprotocol", 7239891], ["google-cloud-automl", 7235951], ["urwid", 7235391], ["daytona-analytics-api-client-async", 7234401], ["daytona-analytics-api-client", 7234149], ["apache-airflow-providers-ssh", 7232065], ["mongomock", 7221636], ["edge-tts", 7208908], ["ag-ui-protocol", 7200805], ["pprintpp", 7196307], ["google-cloud-memcache", 7195463], ["hatch", 7192009], ["google-cloud-os-login", 7183088], ["markdown2", 7179666], ["google-cloud-orchestration-airflow", 7175698], ["kaitaistruct", 7155235], ["deepmerge", 7151266], ["highspy", 7151189], ["xmlschema", 7150855], ["arro3-core", 7146644], ["cookiecutter", 7137752], ["backports-asyncio-runner", 7129778], ["constructs", 7127784], ["sh", 7118450], ["thriftpy2", 7107428], ["cytoolz", 7105473], ["cloud-sql-python-connector", 7095375], ["aniso8601", 7089790], ["py-vapid", 7086473], ["azure-mgmt-containerregistry", 7076560], ["parse-type", 7072829], ["jsii", 7062885], ["google-cloud-dataproc-metastore", 7060045], ["pytest-sugar", 7059048], ["restrictedpython", 7052048], ["func-timeout", 7044277], ["protego", 7035316], ["w3lib", 7015146], ["url-normalize", 7003225], ["ebcdic", 6999627], ["prefect", 6995390], ["requests-ntlm", 6979042], ["cvxpy", 6971721], ["webauthn", 6968235], ["scs", 6967402], ["mypy-protobuf", 6964505], ["starkbank-ecdsa", 6949787], ["python3-openid", 6937015], ["django-environ", 6922655], ["google-cloud-dataflow-client", 6917947], ["publication", 6900193], ["asynctest", 6899261], ["clarabel", 6872914], ["blobfile", 6871781], ["extract-msg", 6868704], ["mutagen", 6867077], ["google-cloud-batch", 6863412], ["autopep8", 6856253], ["restructuredtext-lint", 6852490], ["pamqp", 6848400], ["python-telegram-bot", 6837306], ["braintrust", 6829647], ["tensorflow-estimator", 6825317], ["korean-lunar-calendar", 6823017], ["grpcio-gcp", 6798658], ["compressed-rtf", 6790245], ["auth0-python", 6775971], ["llama-index-core", 6773919], ["python-calamine", 6770099], ["a2wsgi", 6766774], ["webdriver-manager", 6760285], ["avro-python3", 6747248], ["opentelemetry-exporter-http-transport", 6727058], ["priority", 6691570], ["chromadb", 6682584], ["dagster-graphql", 6682246], ["xyzservices", 6678145], ["workos", 6674799], ["firecrawl-anydoc", 6674429], ["slackclient", 6670259], ["apispec", 6668766], ["opentelemetry-instrumentation-psycopg", 6652716], ["aiocache", 6647041], ["pulumi", 6628487], ["funcy", 6621944], ["types-psycopg2", 6614218], ["types-docutils", 6607758], ["aiormq", 6607148], ["textual-speedups", 6592215], ["rtfde", 6586976], ["oldest-supported-numpy", 6583368], ["aio-pika", 6579162], ["lance-namespace-urllib3-client", 6560384], ["azure-storage-common", 6558380], ["databricks-connect", 6555650], ["lance-namespace", 6554131], ["dash", 6546860], ["aws-cdk-lib", 6533071], ["azure-mgmt-containerservice", 6532287], ["dirtyjson", 6528413], ["django-phonenumber-field", 6527880], ["waitress", 6520418], ["dagster-webserver", 6514163], ["dataclasses", 6501967], ["nose", 6495252], ["django-celery-beat", 6494675], ["rfc8785", 6491028], ["etils", 6475191], ["djangorestframework-simplejwt", 6474867], ["lru-dict", 6465093], ["partial-json-parser", 6455735], ["pypng", 6451955], ["apache-airflow-providers-common-compat", 6449831], ["python-decouple", 6449346], ["databricks-labs-dqx", 6447298], ["azure-keyvault", 6437910], ["metricflow", 6433276], ["click-default-group", 6419761], ["google-cloud-discoveryengine", 6402325], ["azure-mgmt-authorization", 6398948], ["sphinx-rtd-theme", 6398082], ["hypercorn", 6390184], ["pyyaml-ft", 6380108], ["audioop-lts", 6379631], ["python3-saml", 6378907], ["mixpanel", 6376194], ["pylatexenc", 6358763], ["apache-airflow-providers-databricks", 6343565], ["parver", 6336323], ["pyahocorasick", 6326970], ["langchain-mcp-adapters", 6323546], ["optree", 6318464], ["harbor-rewardkit", 6301172], ["publicsuffix2", 6298589], ["fake-useragent", 6296398], ["apache-airflow-providers-google", 6294793], ["scantree", 6292884], ["dirhash", 6291551], ["python-on-whales", 6288322], ["json-rpc", 6265854], ["odfpy", 6259283], ["types-openpyxl", 6244810], ["circuitbreaker", 6239538], ["livekit-protocol", 6235155], ["pyhive", 6227289], ["mypy-boto3-glue", 6226377], ["audioread", 6223508], ["types-html5lib", 6219665], ["ortools", 6217068], ["mypy-boto3-sts", 6214364], ["azure-mgmt-datafactory", 6209771], ["allure-python-commons", 6186815], ["ciso8601", 6180914], ["flask-babel", 6178859], ["pyopengl", 6168524], ["mkdocstrings-python", 6165116], ["mkdocstrings", 6138542], ["microsoft-kiota-serialization-multipart", 6128982], ["microsoft-kiota-serialization-form", 6127255], ["mkdocs-autorefs", 6125356], ["dictdiffer", 6107442], ["pympler", 6101776], ["azure-mgmt-containerinstance", 6093016], ["pywin32-ctypes", 6083988], ["pglast", 6074930], ["browser-harness", 6066882], ["stringcase", 6058367], ["livekit-api", 6052264], ["strawberry-graphql", 6048437], ["eth-utils", 6043934], ["dbt-core-experimental-parser", 6041103], ["sphinxcontrib-jquery", 6040193], ["eth-hash", 6040085], ["eth-abi", 6036765], ["enum34", 6028469], ["google-cloud-iam", 6013564], ["python-socks", 6003778], ["eth-typing", 5988690], ["tokenize-rt", 5970278], ["google-analytics-admin", 5964700], ["rlp", 5962931], ["hexbytes", 5960472], ["pastel", 5959293], ["voluptuous", 5954801], ["tyro", 5952618], ["grpcio-reflection", 5951177], ["pyte", 5943366], ["schedule", 5927631], ["azure-mgmt-keyvault", 5925566], ["pyfiglet", 5917869], ["python-crfsuite", 5917374], ["cel-python", 5914407], ["addict", 5909303], ["betterproto", 5884070], ["parsimonious", 5878652], ["msgraph-sdk", 5872230], ["fetch-use", 5859300], ["e2b", 5859291], ["docker-pycreds", 5845211], ["nanoid", 5841768], ["pymupdf-layout", 5839972], ["libtmux", 5837694], ["djangorestframework-stubs", 5831441], ["pyhcl", 5785395], ["pytest-unordered", 5784737], ["imbalanced-learn", 5773279], ["whenever", 5770564], ["pyzstd", 5758678], ["unicodecsv", 5755828], ["tree-sitter-ruby", 5747532], ["codeowners", 5732623], ["types-tqdm", 5727607], ["jsonschema-rs", 5719639], ["torchaudio", 5719226], ["applicationinsights", 5715372], ["types-python-slugify", 5704619], ["jq", 5700825], ["flask-session", 5699510], ["red-black-tree-mod", 5668505], ["pynndescent", 5665443], ["azure-appconfiguration", 5663612], ["rustworkx", 5652569], ["aws-cdk-asset-node-proxy-agent-v6", 5633878], ["allure-pytest", 5614857], ["umap-learn", 5609189], ["dbt-snowflake", 5604718], ["livekit", 5597270], ["flit", 5595510], ["pydicom", 5584991], ["aioresponses", 5578653], ["http-ece", 5576129], ["mutmut", 5573272], ["marko", 5571448], ["fastapi-sso", 5570624], ["deepagents", 5563902], ["poethepoet", 5562771], ["flask-jwt-extended", 5559155], ["opentelemetry-sdk-extension-aws", 5555085], ["types-aioboto3", 5544113], ["firecrawl-py", 5540003], ["aws-cdk-cloud-assembly-schema", 5535534], ["lmnr", 5521689], ["pulp", 5519698], ["opentelemetry-exporter-gcp-monitoring", 5519620], ["pydantic-ai", 5515509], ["presidio-analyzer", 5505794], ["gguf", 5488885], ["opentelemetry-exporter-gcp-logging", 5488663], ["azure-mgmt-monitor", 5483459], ["openai-harmony", 5480041], ["mando", 5472148], ["social-auth-core", 5471766], ["gradio-client", 5468480], ["flask-appbuilder", 5460254], ["setuptools-rust", 5455117], ["radon", 5454590], ["construct", 5446145], ["z3-solver", 5432750], ["apache-tvm-ffi", 5427025], ["sqlite-vec", 5419447], ["databricks-agents", 5407264], ["pint", 5406976], ["types-boto3-s3", 5406070], ["eth-rlp", 5399288], ["pyhocon", 5395150], ["github3-py", 5391560], ["numcodecs", 5390413], ["tree-sitter-yaml", 5389031], ["gradio", 5388562], ["unittest-xml-reporting", 5387967], ["ifaddr", 5373710], ["dspy", 5365274], ["celery-redbeat", 5364102], ["azure-mgmt-sql", 5362342], ["tree-sitter-php", 5359497], ["asteval", 5353844], ["cerberus", 5350783], ["pytest-forked", 5348181], ["catboost", 5344320], ["eth-account", 5340088], ["bokeh", 5331507], ["mangum", 5321683], ["eth-keys", 5318572], ["oci", 5318158], ["azure-mgmt-datalake-store", 5315229], ["ndg-httpsclient", 5314671], ["bedrock-agentcore", 5309483], ["myst-parser", 5299843], ["social-auth-app-django", 5297445], ["inputimeout", 5289448], ["zxcvbn", 5285588], ["django-ipware", 5284716], ["imagehash", 5284571], ["mitmproxy", 5277659], ["pefile", 5269336], ["apache-airflow-providers-smtp", 5267993], ["icdiff", 5267125], ["gprof2dot", 5262219], ["lxml-stubs", 5255307], ["exa-py", 5253102], ["dagster-postgres", 5249141], ["lmnr-claude-code-proxy", 5247726], ["openai-whisper", 5243707], ["editorconfig", 5243576], ["pytest-order", 5243361], ["pyqwest", 5238172], ["yapf", 5225309], ["teradatasql", 5223546], ["ddgs", 5223492], ["methodtools", 5210316], ["opentelemetry-instrumentation-asyncio", 5206813], ["autoflake", 5205897], ["azure-mgmt-web", 5205849], ["pytest-icdiff", 5200112], ["wirerope", 5200056], ["flexparser", 5194334], ["flexcache", 5190937], ["thrift-sasl", 5184142], ["jinxed", 5184001], ["nvidia-nvshmem-cu12", 5183783], ["opencensus-ext-azure", 5181603], ["cadwyn", 5176437], ["nemo-relay", 5175136], ["pypandoc", 5166049], ["diffusers", 5164569], ["eth-keyfile", 5158285], ["probableparsing", 5142745], ["jsbeautifier", 5126604], ["ckzg", 5126267], ["rasterio", 5126027], ["timezonefinder", 5122655], ["affine", 5122335], ["segno", 5120753], ["pyhanko", 5112671], ["pytest-testmon", 5111451], ["python-stdnum", 5109357], ["fastembed", 5108789], ["selectolax", 5103994], ["cross-web", 5101391], ["orderedmultidict", 5099481], ["py-rust-stemmers", 5096018], ["atomicwrites", 5090871], ["curlify", 5086007], ["opentelemetry-instrumentation-kafka-python", 5085084], ["usaddress", 5079231], ["jinja2-humanize-extension", 5072569], ["pytest-recording", 5070621], ["azure-mgmt-redis", 5070269], ["azure-mgmt-network", 5069725], ["furl", 5068012], ["magicattr", 5067985], ["enum-compat", 5056198], ["channels", 5050375], ["iso3166", 5048579], ["openhands-sdk", 5038476], ["tablib", 5035161], ["django-allauth", 5034587], ["banks", 5032375], ["tom-swe", 5031199], ["azure-mgmt-cognitiveservices", 5021293], ["acryl-datahub", 5019402], ["types-retry", 5017749], ["subprocess-tee", 5015093], ["opentelemetry-util-genai", 5012027], ["litellm-proxy-extras", 5010229], ["dlt", 5002981], ["pyhanko-certvalidator", 5001515], ["pymsteams", 4998175], ["pathlib", 4998169], ["zarr", 4997515], ["latex2mathml", 4991117], ["anytree", 4987975], ["azure-ai-agents", 4984957], ["svglib", 4983458], ["numpy-financial", 4982248], ["jieba", 4977130], ["namex", 4976390], ["azure-mgmt-msi", 4972518], ["pulumi-aws", 4964710], ["openhands-tools", 4964688], ["pyhumps", 4963447], ["litellm-enterprise", 4958456], ["harbor", 4946965], ["polib", 4945532], ["llama-index-workflows", 4944438], ["configobj", 4944127], ["pyaml", 4937608], ["opentelemetry-instrumentation-starlette", 4928734], ["cligj", 4924808], ["discord-py", 4921209], ["functions-framework", 4920116], ["standardwebhooks", 4915634], ["diff-match-patch", 4915582], ["codespell", 4902393], ["tree-sitter-cpp", 4901455], ["marshmallow-sqlalchemy", 4897681], ["types-webencodings", 4890876], ["django-simple-history", 4888149], ["dynaconf", 4873678], ["presto-python-client", 4873448], ["mistral-common", 4872661], ["cuda-python", 4861682], ["django-appconf", 4859409], ["python-ipware", 4853638], ["geomet", 4853243], ["premailer", 4839227], ["arabic-reshaper", 4832125], ["turbopuffer", 4827190], ["llama-index-instrumentation", 4826521], ["azure-nspkg", 4825742], ["apache-airflow-providers-http", 4822290], ["pi-heif", 4816957], ["mistral-vibe", 4808151], ["azure-synapse-artifacts", 4796662], ["rdkit", 4794896], ["pyluach", 4782854], ["port-for", 4780344], ["django-oauth-toolkit", 4772111], ["flask-caching", 4768688], ["azure-mgmt-loganalytics", 4761699], ["plumbum", 4759573], ["aliyun-python-sdk-core", 4757294], ["disposable-email-domains", 4754835], ["pygit2", 4749873], ["django-model-utils", 4739634], ["bullmq", 4735873], ["html-to-markdown", 4734176], ["httpx-aiohttp", 4728908], ["azure-mgmt-eventhub", 4726823], ["structlog-sentry", 4715517], ["ezdxf", 4713694], ["phonenumberslite", 4710540], ["pytest-dotenv", 4710221], ["azure-mgmt-applicationinsights", 4709925], ["opentelemetry-instrumentation-sqlite3", 4706208], ["tach", 4700233], ["azure-mgmt-rdbms", 4695299], ["web3", 4694766], ["distributed", 4694353], ["valkey", 4693339], ["requests-cache", 4688600], ["pipdeptree", 4686514], ["pytest-aiohttp", 4680305], ["nats-py", 4670723], ["xai-sdk", 4664035], ["opentelemetry-instrumentation-pymongo", 4662635], ["docx2txt", 4660515], ["sqlparams", 4657522], ["uamqp", 4647182], ["aws-msk-iam-sasl-signer-python", 4646518], ["pex", 4645349], ["greenback", 4636530], ["azure-mgmt-servicebus", 4634404], ["dependency-groups", 4631915], ["webob", 4631764], ["nvidia-cutlass-dsl-libs-base", 4624177], ["google-analytics-data", 4601037], ["ddtrace-internal", 4592367], ["azure-synapse-spark", 4584579], ["yaspin", 4580859], ["expression", 4578180], ["appium-python-client", 4575108], ["svcs", 4572059], ["python-box", 4566384], ["azure-functions", 4561970], ["apache-airflow-providers-slack", 4559728], ["azure-search-documents", 4552642], ["azure-mgmt-cdn", 4552093], ["tensorflow-serving-api", 4538850], ["pure-sasl", 4525964], ["xgrammar", 4523950], ["safety", 4514617], ["django-otp", 4514318], ["dbt-spark", 4498597], ["tensorflow-text", 4492184], ["marshmallow-dataclass", 4484315], ["sly", 4481248], ["daphne", 4475851], ["environs", 4452256], ["azure-mgmt-eventgrid", 4441441], ["azure-mgmt-recoveryservices", 4438682], ["openlineage-python", 4438451], ["hdfs", 4428874], ["boto", 4428794], ["moviepy", 4424741], ["intervaltree", 4418277], ["ipython-genutils", 4417466], ["apache-airflow-providers-fab", 4398021], ["azure-mgmt-search", 4394977], ["azure-mgmt-recoveryservicesbackup", 4390674], ["geoalchemy2", 4384716], ["pkgconfig", 4383136], ["backports-zoneinfo", 4378877], ["reductoai", 4376080], ["multipart", 4374825], ["apache-airflow-providers-cncf-kubernetes", 4369988], ["choreographer", 4365687], ["azure-mgmt-managementgroups", 4358218], ["aiohttp-socks", 4353634], ["elasticsearch-dsl", 4352597], ["scrapy", 4350762], ["pydantic-monty", 4350039], ["tinytag", 4348935], ["typing", 4337033], ["stamina", 4323262], ["parsy", 4322942], ["memory-profiler", 4317587], ["prance", 4317168], ["azure-mgmt-batch", 4314898], ["json-merge-patch", 4312734], ["mpire", 4283526], ["requests-futures", 4280751], ["logistro", 4280414], ["asyncstdlib", 4278346], ["docling-core", 4277206], ["pylsqpack", 4275241], ["hatch-fancy-pypi-readme", 4264923], ["tableauserverclient", 4261532], ["types-six", 4259941], ["ultralytics", 4251823], ["django-csp", 4243950], ["python-keycloak", 4240937], ["glfw", 4238988], ["reactivex", 4236514], ["azure-mgmt-trafficmanager", 4231365], ["google-cloud-datastore", 4229665], ["zizmor", 4221198], ["connexion", 4220097], ["kgb", 4215566], ["aioquic", 4215514], ["azure-mgmt-iothub", 4215366], ["proglog", 4214396], ["facebook-business", 4214247], ["safehttpx", 4212504], ["llguidance", 4208592], ["dbt-postgres", 4204278], ["cuda-core", 4200928], ["janus", 4199052], ["checkov", 4194699], ["google", 4192115], ["portkey-ai", 4190652], ["editor", 4184641], ["biopython", 4177345], ["autoevals", 4175600], ["tree-sitter-language-pack", 4169896], ["azure-kusto-ingest", 4168879], ["azure-eventgrid", 4160018], ["apache-airflow-providers-common-io", 4153181], ["azure-mgmt-marketplaceordering", 4151709], ["xmod", 4142973], ["patch-ng", 4141628], ["cmdstanpy", 4140502], ["pyarrow-stubs", 4139980], ["nvidia-cutlass-dsl", 4138314], ["dagster-cloud-cli", 4134961], ["pyairtable", 4133303], ["mujoco", 4131446], ["azure-mgmt-advisor", 4130256], ["polyleven", 4127148], ["azure-devops", 4125904], ["knack", 4125899], ["pydocstyle", 4124752], ["google-cloud-alloydb", 4099566], ["azure-mgmt-policyinsights", 4092904], ["python-tds", 4092088], ["jaxtyping", 4091878], ["azure-mgmt-servicefabric", 4086690], ["python-oxmsg", 4086687], ["aiostream", 4085110], ["prophet", 4084307], ["dagster-aws", 4082741], ["logbook", 4080323], ["robotframework", 4070640], ["compressed-tensors", 4064681], ["keras-applications", 4064483], ["unearth", 4060003], ["multipledispatch", 4058387], ["arxiv", 4055165], ["azure-mgmt-signalr", 4052386], ["inquirer", 4051892], ["opentelemetry-instrumentation-aiokafka", 4049133], ["pystache", 4045450], ["channels-redis", 4044083], ["multimethod", 4041601], ["semchunk", 4038219], ["newrelic", 4036185], ["azure-mgmt-datamigration", 4032081], ["azure-ai-inference", 4031391], ["googlesearch-python", 4031221], ["pytest-httpserver", 4027100], ["spdx-tools", 4026741], ["azure-mgmt-billing", 4022903], ["snowflake-core", 4022890], ["azure-mgmt-media", 4017905], ["azure-mgmt-maps", 4013287], ["pycurl", 4010405], ["asgi-correlation-id", 4009854], ["azure-mgmt-iothubprovisioningservices", 4005653], ["runs", 4005601], ["azure-mgmt-batchai", 4001688], ["azure-mgmt-iotcentral", 3997564], ["lightning", 3993173], ["donfig", 3988818], ["pytest-postgresql", 3987990], ["pycomposefile", 3985584], ["pinecone", 3977957], ["py-key-value-shared", 3971963], ["pdm", 3971145], ["sql-metadata", 3968690], ["shellcheck-py", 3966953], ["datasketch", 3959197], ["llama-index-llms-openai", 3957005], ["pyleak", 3945252], ["pyaes", 3941927], ["opentelemetry-processor-baggage", 3937166], ["multi-key-dict", 3917335], ["ultralytics-thop", 3916030], ["timeout-decorator", 3915372], ["opentelemetry-instrumentation-boto3sqs", 3915053], ["bitstring", 3908169], ["llama-index-embeddings-openai", 3895136], ["encutils", 3882002], ["ua-parser-rs", 3879681], ["rapidocr", 3876279], ["azure-mgmt-appcontainers", 3868723], ["arq", 3864336], ["patchright", 3864199], ["dbt-databricks", 3850522], ["mirakuru", 3847992], ["types-pillow", 3843498], ["wadler-lindig", 3836875], ["nox", 3835419], ["exchange-calendars", 3833455], ["python-barcode", 3828759], ["opentelemetry-instrumentation-jinja2", 3827152], ["hjson", 3825502], ["clang-format", 3822576], ["ansible-compat", 3814574], ["sagemaker-core", 3808105], ["behave", 3803524], ["djangorestframework-csv", 3803287], ["simple-gcp-object-downloader", 3798823], ["fastapi-pagination", 3792453], ["presidio-anonymizer", 3790069], ["interegular", 3775730], ["django-prometheus", 3759597], ["pymilvus", 3757341], ["pytest-custom-exit-code", 3752357], ["dep-logic", 3741481], ["detect-test-pollution", 3740542], ["pipx", 3739553], ["voyageai", 3736883], ["problog", 3735373], ["cassandra-driver", 3733662], ["aiomultiprocess", 3725668], ["pytest-subtests", 3724462], ["commonmark", 3721529], ["django-axes", 3718962], ["xhtml2pdf", 3718050], ["statsig", 3711919], ["pyiceberg-core", 3710187], ["dbt-bigquery", 3704836], ["statsig-python-core", 3704428], ["blockbuster", 3704101], ["bc-detect-secrets", 3695698], ["hatch-requirements-txt", 3695053], ["celery-types", 3694190], ["outlines-core", 3693784], ["terminaltables", 3688767], ["pathlib2", 3686883], ["tzfpy", 3682021], ["groovy", 3681129], ["python-rapidjson", 3678950], ["jiwer", 3678133], ["django-celery-results", 3676706], ["gymnasium", 3667321], ["azure-graphrbac", 3658663], ["types-defusedxml", 3653869], ["types-simplejson", 3651668], ["pdbr", 3648597], ["torch-c-dlpack-ext", 3647181], ["stanio", 3642745], ["rfc3987", 3640898], ["click-log", 3638753], ["modelscope", 3635809], ["aliyun-python-sdk-kms", 3635710], ["flask-migrate", 3632869], ["promise", 3630975], ["azure-mgmt-privatedns", 3624493], ["mitmproxy-rs", 3618666], ["apache-beam", 3618573], ["django-ninja", 3606272], ["anyascii", 3605566], ["bluetooth-data-tools", 3604892], ["sqlglotrs", 3593619], ["freetype-py", 3588327], ["pyusb", 3586940], ["prison", 3585919], ["segment-analytics-python", 3585181], ["zipstream-ng", 3579732], ["regress", 3575215], ["google-cloud-vectorsearch", 3571655], ["python-ldap", 3570746], ["ibm-db", 3570434], ["haversine", 3563655], ["types-beautifulsoup4", 3561916], ["farama-notifications", 3558892], ["lark-parser", 3557890], ["tensorboardx", 3555267], ["ibis-framework", 3552581], ["policy-sentry", 3551309], ["livekit-agents", 3547868], ["checkdigit", 3545800], ["bitsandbytes", 3544451], ["opentelemetry-instrumentation-aws-lambda", 3542528], ["convertdate", 3541846], ["docling-parse", 3536061], ["intelhex", 3527541], ["hf-transfer", 3527395], ["influxdb-client", 3524008], ["apache-airflow-providers-amazon", 3523828], ["fastapi-mcp", 3519668], ["docxtpl", 3514327], ["cloudsplaining", 3512489], ["legacy-cgi", 3511614], ["decli", 3511263], ["django-structlog", 3507592], ["azure-mgmt-apimanagement", 3502148], ["backports-strenum", 3501219], ["opentelemetry-instrumentation-tortoiseorm", 3494481], ["pylance", 3491641], ["jaconv", 3488815], ["accessible-pygments", 3488347], ["injector", 3487117], ["pycep-parser", 3485198], ["datacompy", 3485087], ["hubspot-api-client", 3484424], ["tensorflow-io-gcs-filesystem", 3481401], ["conan", 3473e3], ["parsel", 3471381], ["flatten-dict", 3470284], ["bc-python-hcl2", 3469301], ["pysbd", 3468153], ["django-health-check", 3466706], ["munch", 3460250], ["schedula", 3460198], ["pwdlib", 3457999], ["marshmallow-oneofschema", 3455966], ["opentelemetry-propagator-b3", 3450136], ["apache-airflow-providers-imap", 3447190], ["notion-client", 3444715], ["dagster-k8s", 3443294], ["dagster-cloud", 3443037], ["jdcal", 3434478], ["pip-licenses", 3434413], ["hijridate", 3427276], ["django-migration-linter", 3422509], ["django-formtools", 3420752], ["base58", 3417768], ["formulas", 3416212], ["javaproperties", 3412757], ["livekit-blingfire", 3408602], ["tinydb", 3406125], ["pysmb", 3405352], ["apache-airflow-providers-ftp", 3381594], ["protobuf-py-ext", 3378965], ["cftime", 3377387], ["ddsketch", 3376779], ["dparse", 3372072], ["bc-jsonpath-ng", 3363739], ["cloudscraper", 3361508], ["typed-ast", 3354903], ["shtab", 3354057], ["geojson", 3353855], ["jupytext", 3349908], ["protobuf-py", 3342673], ["sphinx-copybutton", 3341113], ["wget", 3338879], ["vercel-runtime", 3333557], ["nvidia-cudnn-frontend", 3333502], ["databricks-sqlalchemy", 3333245], ["duckduckgo-search", 3328025], ["types-boto3-ses", 3319667], ["scipy-stubs", 3315832], ["async-generator", 3312997], ["opentelemetry-instrumentation-tornado", 3309398], ["minimal-snowplow-tracker", 3307697], ["chdb", 3302339], ["scapy", 3299430], ["google-cloud-managedkafka", 3298464], ["latex2sympy2-extended", 3293018], ["httpx-retries", 3292743], ["pytest-instafail", 3290897], ["pymeeus", 3288862], ["pdfrw", 3288470], ["simsimd", 3287552], ["unstructured-client", 3286309], ["zict", 3284458], ["sqlalchemy-redshift", 3283331], ["ansible-lint", 3281182], ["azure-cli-core", 3278501], ["autograd", 3278428], ["azure-mgmt-postgresqlflexibleservers", 3276456], ["alibabacloud-tea-openapi", 3273751], ["fixedint", 3272056], ["ipaddress", 3272030], ["algoliasearch", 3267379], ["azure-mgmt-security", 3267276], ["pydantic-monty-runtime", 3262482], ["typepy", 3261896], ["mbstrdecoder", 3261587], ["pyfakefs", 3261477], ["sphinxcontrib-mermaid", 3257255], ["pyshp", 3253862], ["pdpyras", 3252967], ["pulumi-command", 3252967], ["llama-cloud", 3252449], ["optype", 3252375], ["py-cpuinfo2", 3252305], ["apache-airflow-providers-sqlite", 3249018], ["quack-kernels", 3246390], ["deepgram-sdk", 3246292], ["django-js-asset", 3244829], ["aiologic", 3243128], ["nameparser", 3242716], ["click-aliases", 3241769], ["vtk", 3240728], ["opentracing", 3239894], ["google-cloud-documentai", 3235404], ["sacrebleu", 3234300], ["python-can", 3232342], ["azure-mgmt-appconfiguration", 3226347], ["onepassword-sdk", 3224495], ["connectrpc", 3224390], ["torchcodec", 3219153], ["mypy-boto3-ssm", 3216983], ["azure-mgmt-hdinsight", 3215464], ["math-verify", 3203091], ["zenpy", 3199486], ["mypy-boto3-bedrock-runtime", 3198494], ["rjsmin", 3186772], ["grpc-stubs", 3185651], ["googlemaps", 3183347], ["pyside6-essentials", 3182061], ["aws-encryption-sdk", 3179010], ["mail-parser", 3177293], ["spake2", 3176402], ["openapi-python-client", 3174703], ["docling-ibm-models", 3173377], ["pdm-backend", 3171434], ["pytest-bdd", 3169827], ["txtorcon", 3166871], ["gdown", 3166720], ["quart", 3165336], ["magic-wormhole", 3163680], ["pusher", 3156934], ["opentelemetry-instrumentation-pymysql", 3153592], ["pyyaml-include", 3150983], ["fiona", 3149070], ["pylint-plugin-utils", 3148446], ["databricks-labs-lsql", 3147854], ["hypothesis-graphql", 3142302], ["nulltype", 3140234], ["iterable-io", 3139441], ["netcdf4", 3138667], ["html-for-docx", 3134158], ["opentelemetry-instrumentation-pika", 3132063], ["azure-mgmt-synapse", 3131289], ["pyzbar", 3130729], ["alibabacloud-credentials", 3129673], ["check-jsonschema", 3121943], ["azure-mgmt-mysqlflexibleservers", 3121558], ["django-anymail", 3113154], ["crcmod-plus", 3112393], ["pydispatcher", 3109311], ["opentelemetry-instrumentation-vertexai", 3108561], ["llama-index", 3108313], ["microsoft-security-utilities-secret-masker", 3107932], ["schemathesis", 3107361], ["google-cloud-artifact-registry", 3103759], ["browserbase", 3102419], ["pytest-factoryboy", 3100306], ["dm-tree", 3099890], ["kazoo", 3092013], ["flashinfer-python", 3091726], ["yq", 3090307], ["python-jenkins", 3084173], ["opentelemetry-instrumentation-falcon", 3082076], ["alibabacloud-oss-v2", 3080604], ["parallel-web", 3077242], ["djlint", 3071495], ["pyunormalize", 3068037], ["vertica-python", 3050122], ["shiboken6", 3049943], ["opentelemetry-instrumentation-aio-pika", 3048835], ["opentelemetry-instrumentation-anthropic", 3048273], ["azure-cli-telemetry", 3045817], ["cssbeautifier", 3040456], ["yappi", 3040304], ["sqlalchemy-jsonfield", 3031015], ["mdformat", 3030135], ["commitizen", 3029723], ["pdfkit", 3028321], ["azure-mgmt-redhatopenshift", 3027034], ["pytest-random-order", 3024001], ["azure-cli", 3022637], ["types-mock", 3017087], ["pymongo-auth-aws", 3011663], ["openlineage-sql", 3007988], ["rcssmin", 3004648], ["opentelemetry-instrumentation-confluent-kafka", 3002948], ["azure-keyvault-administration", 3000660], ["libsass", 2997928], ["asyncpg-stubs", 2997280], ["pyjson5", 2994484], ["gensim", 2991294], ["azure-mgmt-netapp", 2988526], ["tweepy", 2986743], ["fastexcel", 2986667], ["tox-uv", 2981610], ["azure-mgmt-sqlvirtualmachine", 2975854], ["numpy-typing-compat", 2975242], ["versioneer", 2974499], ["asana", 2971747], ["suds-community", 2969113], ["azure-mgmt-servicefabricmanagedclusters", 2969090], ["json-log-formatter", 2968598], ["openlineage-integration-common", 2967778], ["flatten-json", 2967731], ["harfile", 2963752], ["pynamodb", 2963001], ["azure-synapse-accesscontrol", 2962210], ["opentelemetry-instrumentation-pyramid", 2959236], ["evaluate", 2958199], ["wikipedia-api", 2954677], ["sphinx-design", 2951723], ["tilelang", 2950835], ["culsans", 2950163], ["azure-mgmt-resource-deployments", 2948061], ["dagster-dg-cli", 2944383], ["dagster-slack", 2944128], ["pinecone-plugin-interface", 2943915], ["dagster-dg-core", 2940845], ["azure-mgmt-botservice", 2940464], ["clickclick", 2939224], ["doclang", 2937762], ["azure-communication-email", 2937e3], ["azure-mgmt-imagebuilder", 2936316], ["telethon", 2934449], ["azure-mgmt-extendedlocation", 2932224], ["azure-synapse-managedprivateendpoints", 2932162], ["opentelemetry-instrumentation-mysqlclient", 2931813], ["pyside6-addons", 2928426], ["configupdater", 2925741], ["azure-mgmt-servicelinker", 2922139], ["ip3country", 2921623], ["docling", 2914308], ["plaid-python", 2913830], ["types-regex", 2912495], ["hf-gradio", 2910212], ["sglang", 2908200], ["ast-grep-cli", 2898240], ["tree-sitter-powershell", 2896060], ["ffmpy", 2895444], ["css-inline", 2895246], ["lingua-language-detector", 2893516], ["pypandoc-binary", 2891797], ["azure-mgmt-nspkg", 2891273], ["pydantic-ai-harness", 2890693], ["types-httplib2", 2884189], ["textblob", 2881824], ["mypy-boto3-iam", 2880973], ["hijri-converter", 2880638], ["alembic-postgresql-enum", 2879666], ["opentelemetry-instrumentation-langchain", 2876034], ["pycocotools", 2875717], ["pytest-check", 2873797], ["salesforce-bulk", 2869896], ["gherkin-official", 2868186], ["opentelemetry-instrumentation-openai", 2866738], ["py-deviceid", 2866433], ["hishel", 2866262], ["albumentations", 2864322], ["result", 2858313], ["fhir-resources", 2857820], ["toons", 2856507], ["python-iso639", 2856063], ["xsdata", 2852479], ["h5netcdf", 2849356], ["pymemcache", 2848440], ["zipfile-zstd", 2843854], ["boxsdk", 2840730], ["fal-client", 2839231], ["flake8-bugbear", 2838182], ["pytimeparse2", 2835935], ["pulumi-tls", 2835061], ["aws-psycopg2", 2832813], ["optax", 2824643], ["concurrent-log-handler", 2824541], ["publicsuffixlist", 2823415], ["google-cloud", 2822962], ["mypy-boto3-ecs", 2821666], ["mssql-python", 2820857], ["flaky", 2819099], ["asciinema", 2814602], ["forbiddenfruit", 2810818], ["astropy", 2810208], ["pyloudnorm", 2810200], ["pyod", 2808497], ["pytest-github-actions-annotate-failures", 2805491], ["inspect-ai", 2801864], ["playwright-stealth", 2798030], ["pyhamcrest", 2797013], ["types-aiobotocore-sqs", 2793963], ["snakeviz", 2793824], ["tree-sitter-embedded-template", 2788952], ["resampy", 2785888], ["python-arango", 2784950], ["django-two-factor-auth", 2779723], ["assemblyai", 2779381], ["modelscope-hub", 2778637], ["llama-parse", 2778402], ["pyside6", 2778293], ["types-ujson", 2772902], ["pydantic-monty-client", 2770569], ["gcovr", 2766678], ["swesmith", 2764409], ["tree-sitter-json", 2763866], ["django-hijack", 2761568], ["opentelemetry-instrumentation-mysql", 2756383], ["docling-slim", 2756170], ["igraph", 2750721], ["py-ecc", 2750466], ["sagemaker-studio", 2748234], ["openfeature-sdk", 2745319], ["django-linear-migrations", 2743549], ["langgraph-checkpoint-sqlite", 2742948], ["dbos", 2740450], ["databricks-pypi1", 2737137], ["django-polymorphic", 2735638], ["apache-airflow-core", 2735430], ["pytest-retry", 2731494], ["pyerfa", 2729996], ["sparklines", 2728554], ["clerk-backend-api", 2728443], ["gspread-dataframe", 2725491], ["pytest-durations", 2722338], ["flask-compress", 2712582], ["alibabacloud-tea", 2712338], ["futures", 2709618], ["pytest-memray", 2708735], ["jwt", 2707125], ["aiogram", 2706654], ["djangorestframework-api-key", 2700701], ["cloudinary", 2699850], ["opentelemetry-instrumentation-pymemcache", 2699257], ["azure-keyvault-securitydomain", 2695900], ["requests-unixsocket", 2695268], ["uuid", 2693620], ["llama-index-readers-file", 2692504], ["pyglet", 2689247], ["editdistance", 2689044], ["querystring-parser", 2687466], ["azure-mgmt-resource-deploymentstacks", 2687228], ["easydict", 2684530], ["funcsigs", 2682696], ["psygnal", 2680568], ["nvidia-cuda-cccl", 2679214], ["awslambdaric", 2678940], ["influxdb", 2676566], ["apache-airflow-providers-standard", 2670593], ["google-api-python-client-stubs", 2669056], ["pystac", 2667420], ["azure-mgmt-datalake-nspkg", 2667329], ["lmdb", 2666220], ["fido2", 2666063], ["mypy-boto3-sns", 2662029], ["markdown-to-mrkdwn", 2658006], ["pytest-vcr", 2656416], ["gotrue", 2656244], ["pykwalify", 2652763], ["opentelemetry-instrumentation-cassandra", 2652355], ["trl", 2651831], ["kfp-pipeline-spec", 2651662], ["opentelemetry-instrumentation-aiopg", 2650694], ["pydantic-xml", 2642291], ["alive-progress", 2641505], ["marisa-trie", 2641026], ["azure-ai-ml", 2637608], ["nvidia-cutlass-dsl-libs-cu13", 2635961], ["opentelemetry-instrumentation-remoulade", 2633959], ["scrapy-playwright", 2631646], ["mypy-boto3-ecr", 2631080], ["lm-format-enforcer", 2630606], ["django-compressor", 2629687], ["livekit-local-inference", 2628680], ["redis-py-cluster", 2622587], ["loro", 2622481], ["commentjson", 2619751], ["eventlet", 2618794], ["orbax-checkpoint", 2617510], ["azure-mgmt-resource-templatespecs", 2616974], ["arviz", 2616850], ["azure-mgmt-resource-deploymentscripts", 2616058], ["portpicker", 2614927], ["zeroconf", 2613549], ["capstone", 2613431], ["snowflake-legacy", 2611918], ["bitstruct", 2609800], ["deepeval", 2601878], ["langgraph-cli", 2601742], ["about-time", 2600972], ["mypy-boto3-stepfunctions", 2600931], ["marimo", 2600241], ["o365", 2596054], ["browser-cookie3", 2595603], ["kfp-server-api", 2591797], ["import-deps", 2589120], ["scandir", 2589118], ["sarif-om", 2587075], ["openapi-core", 2586378], ["google-cloud-pubsublite", 2584206], ["magic-filter", 2581748], ["unstructured", 2581690], ["dashscope", 2581422], ["pymsgbox", 2577346], ["jinja2-simple-tags", 2573909], ["snowflake", 2573501], ["python-xlib", 2570212], ["pyautogui", 2567799], ["e2b-code-interpreter", 2565238], ["pygetwindow", 2560778], ["pytweening", 2556359], ["pytest-timeouts", 2551837], ["repoze-lru", 2548486], ["tensorstore", 2541666], ["opentelemetry-instrumentation-google-genai", 2539362], ["pyscreeze", 2539319], ["cuda-tile", 2537718], ["standard-aifc", 2531674], ["pandasql", 2530803], ["pyrect", 2530654], ["standard-chunk", 2527209], ["julius", 2525364], ["transitions", 2525311], ["types-pygments", 2522258], ["yaml-config", 2521927], ["usaddress-scourgify", 2519745], ["flupy", 2519570], ["astropy-iers-data", 2519482], ["pysaml2", 2510753], ["nvidia-cutlass-dsl-libs-cu12", 2509762], ["braintrust-core", 2505887], ["tibs", 2505531], ["rapidocr-onnxruntime", 2502721], ["types-freezegun", 2502635], ["depyf", 2502333], ["img2pdf", 2501266], ["sparkmeasure", 2500985], ["gitignore-parser", 2499631], ["azure-cognitiveservices-speech", 2498841], ["sqlfluff-templater-dbt", 2498395], ["livekit-plugins-openai", 2493750], ["djangorestframework-dataclasses", 2492065], ["gnupg", 2488031], ["nvidia-nvvm", 2487640], ["mouseinfo", 2484366], ["crewai", 2483836], ["azure-mgmt-subscription", 2483724], ["pymatting", 2481350], ["tree-sitter-kotlin", 2479232], ["docker-image-py", 2477727], ["dataproperty", 2475491], ["nanobind", 2474675], ["comfyui-workflow-templates", 2474420], ["pycrdt", 2472233], ["rstr", 2467957], ["chroma-hnswlib", 2465332], ["braceexpand", 2463701], ["rembg", 2458610], ["sphinx-autodoc-typehints", 2458046], ["nvidia-cuda-nvcc", 2455756], ["appnope", 2453013], ["click-spinner", 2451292], ["flake8-pyproject", 2449574], ["tree-sitter-swift", 2446721], ["cucumber-tag-expressions", 2442911], ["llama-cloud-services", 2442319], ["flashtext", 2442292], ["openinference-instrumentation-langchain", 2441861], ["sqlalchemy2-stubs", 2441454], ["mizani", 2430419], ["queuelib", 2430372], ["anywidget", 2430237], ["livekit-plugins-silero", 2428674], ["cx-oracle", 2427773], ["tabledata", 2423864], ["devtools", 2421886], ["jaraco-text", 2418626], ["supafunc", 2417296], ["opentelemetry-propagator-jaeger", 2416454], ["ibm-cloud-sdk-core", 2416218], ["pycairo", 2415688], ["oras", 2414311], ["pywinrm", 2413190], ["django-import-export", 2412832], ["tox-uv-bare", 2411168], ["pytablewriter", 2408008], ["qtpy", 2407981], ["plotnine", 2407364], ["arpeggio", 2405166], ["dirty-equals", 2404312], ["zlib-ng", 2401028], ["pastedeploy", 2398612], ["casbin", 2398177], ["apache-airflow-task-sdk", 2397281], ["free-email-domains", 2395644], ["blosc2", 2394489], ["tbb", 2394086], ["pip-system-certs", 2392662], ["inject", 2392444], ["comfyui-workflow-templates-core", 2391855], ["ccxt", 2390394], ["dotty-dict", 2388979], ["types-boto3-sqs", 2387408], ["hdbcli", 2386683], ["aws-secretsmanager-caching", 2386525], ["requests-aws-sign", 2385186], ["comfyui-workflow-templates-media-assets-01", 2384840], ["stringzilla", 2383404], ["pydruid", 2380690], ["snapshot-restore-py", 2378935], ["albucore", 2375466], ["mypy-boto3-athena", 2374891], ["nvidia-cuda-crt", 2372770], ["types-grpcio", 2372365], ["pydantic-yaml", 2369304], ["fhir-core", 2367822], ["zc-lockfile", 2365208], ["iterative-telemetry", 2363987], ["coincurve", 2362496], ["appier", 2359459], ["async-property", 2356718], ["nvidia-cutlass-dsl-libs-core", 2356267], ["comfyui-workflow-templates-json", 2355980], ["expandvars", 2353356], ["dataclass-wizard", 2351661], ["resvg-py", 2346906], ["capi-param-builder-python", 2343951], ["yamale", 2337514], ["opentelemetry-propagator-ot-trace", 2335694], ["aws-bedrock-token-generator", 2335368], ["pulumi-random", 2334129], ["pygame", 2333332], ["venusian", 2331811], ["ecs-logging", 2329868], ["cloudflare", 2324513], ["apify-client", 2323162], ["dify-plugin", 2320532], ["pytest-profiling", 2319720], ["django-silk", 2316921], ["language-data", 2316835], ["langgraph-runtime-inmem", 2310736], ["wordfreq", 2310467], ["alembic-utils", 2309369], ["pytest-dependency", 2308593], ["pytest-lazy-fixtures", 2308234], ["honcho", 2307515], ["cheroot", 2307464], ["cucumber-expressions", 2305451], ["django-pydantic-field", 2299161], ["netifaces", 2297409], ["alibabacloud-endpoint-util", 2292821], ["itemadapter", 2284632], ["mss", 2282852], ["pycron", 2281748], ["pytube", 2281649], ["azure-mgmt-containerregistrytasks", 2280127], ["types-markupsafe", 2280067], ["casefy", 2280030], ["pagerduty", 2279960], ["django-reversion", 2277960], ["types-jinja2", 2276969], ["model-hosting-container-standards", 2276521], ["openinference-instrumentation-openai", 2272116], ["datadog-lambda", 2271342], ["webargs", 2269542], ["locate", 2268817], ["langgraph-api", 2268675], ["itemloaders", 2266712], ["hashids", 2266425], ["grandalf", 2265099], ["google-api", 2264812], ["flask-admin", 2260892], ["django-crispy-forms", 2260820], ["cron-converter", 2257569], ["types-boto3-dynamodb", 2253683], ["pytest-codspeed", 2252013], ["flask-socketio", 2250704], ["django-ratelimit", 2249157], ["comfy-kitchen", 2246515], ["azure-mgmt-resourcegraph", 2244443], ["mdutils", 2242682], ["hupper", 2242115], ["chess", 2241734], ["inline-snapshot", 2240474], ["tree-sitter-elixir", 2239059], ["types-boto3-rds", 2238595], ["pytest-docker", 2236945], ["starlette-testclient", 2234247], ["databricks-pypi2", 2231381], ["json-logic", 2231142], ["ebooklib", 2229321], ["django-object-actions", 2228726], ["pygeohash", 2226180], ["types-boto3-ec2", 2225987], ["hypothesis-jsonschema", 2225750], ["kornia", 2224309], ["python-nvd3", 2219106], ["pymediainfo", 2217626], ["jproperties", 2216459], ["tokenspeed-triton", 2215895], ["tcmlib", 2214526], ["scim2-filter-parser", 2214443], ["better-profanity", 2211134], ["aws-lambda-typing", 2209995], ["dbutils", 2208196], ["types-boto3-lambda", 2205209], ["aws-opentelemetry-distro", 2197233], ["pydantic-handlebars", 2195296], ["python-baseconv", 2194860], ["piexif", 2194711], ["types-colorama", 2193328], ["sgqlc", 2192137], ["types-werkzeug", 2190485], ["json-schema-to-pydantic", 2189446], ["types-lxml", 2189247], ["zope-deprecation", 2187141], ["mcap", 2185123], ["flax", 2184603], ["flask-talisman", 2183422], ["branca", 2183294], ["webvtt-py", 2175843], ["torchao", 2175225], ["drf-extensions", 2171226], ["leb128", 2171039], ["ossdata", 2170532], ["adbc-driver-manager", 2169971], ["oyaml", 2169859], ["quickjs", 2166661], ["clickhouse-sqlalchemy", 2165332], ["casadi", 2165079], ["filterpy", 2164706], ["django-admin-sortable2", 2164085], ["hdbscan", 2163441], ["pyspellchecker", 2162110], ["flask-restful", 2161652], ["rarfile", 2156974], ["testfixtures", 2151482], ["furo", 2151044], ["signxml", 2147956], ["asynch", 2146716], ["safety-schemas", 2143747], ["folium", 2143230], ["pkce", 2141798], ["onnxscript", 2139301], ["dominate", 2139084], ["fasttext-wheel", 2138773], ["line-profiler", 2136405], ["tokenspeed-mla", 2130775], ["poetry-dynamic-versioning", 2129594], ["vllm", 2126948], ["dagster-docker", 2124794], ["azure-monitor-ingestion", 2122404], ["cvss", 2117798], ["dynamodb-json", 2113874], ["taskiq", 2112741], ["borb", 2110047], ["x-wr-timezone", 2108803], ["pystac-core", 2106859], ["pystac-ext-raster", 2106006], ["pystac-ext-file", 2105816], ["pystac-ext-eo", 2105591], ["pystac-ext-classification", 2105568], ["pystac-ext-projection", 2105560], ["pystac-ext-sar", 2105532], ["pystac-ext-version", 2105529], ["pystac-ext-sat", 2105512], ["pystac-ext-view", 2105504], ["pystac-ext-xarray-assets", 2105501], ["pystac-ext-item-assets", 2105497], ["pystac-ext-timestamps", 2105497], ["pystac-ext-table", 2105482], ["pystac-ext-scientific", 2105473], ["pystac-ext-pointcloud", 2105461], ["pystac-ext-mgrs", 2105457], ["pystac-ext-grid", 2105434], ["pystac-ext-storage", 2105430], ["pystac-ext-mlm", 2105417], ["pystac-ext-label", 2105416], ["pystac-ext-datacube", 2104507], ["recurring-ical-events", 2104447], ["pystac-ext-render", 2102847], ["comfyui-frontend-package", 2102201], ["sphinx-basic-ng", 2098851], ["pytest-celery", 2096590], ["manifold3d", 2096405], ["onnxruntime-gpu", 2095966], ["aws-embedded-metrics", 2091251], ["flufl-lock", 2091022], ["taskiq-dependencies", 2090012], ["azure-mgmt-domainregistration", 2085839], ["astronomer-cosmos", 2085139], ["wasmtime", 2083838], ["onnx-ir", 2080557], ["mem0ai", 2079950], ["prometheus-flask-exporter", 2079348], ["roman-numerals-py", 2076827], ["types-boto3-cloudformation", 2076529], ["puccinialin", 2074906], ["emr-notebooks-magics", 2073055], ["sacremoses", 2071811], ["pyqt5", 2068352], ["prefect-aws", 2066918], ["mimesis", 2066620], ["keyrings-alt", 2066399], ["isal", 2065036], ["types-bleach", 2061441], ["webdataset", 2057448], ["rx", 2054752], ["kornia-rs", 2051362], ["expecttest", 2049847], ["translationstring", 2048744], ["django-pgactivity", 2046683], ["pykakasi", 2045450], ["undetected-chromedriver", 2045234], ["singer-sdk", 2042861], ["word2number", 2041494], ["configcat-client", 2040673], ["uwsgi", 2038918], ["mypy-boto3-kms", 2038830], ["mssql-python-odbc", 2037787], ["pyscaffold", 2037532], ["drf-yasg", 2035201], ["tcolorpy", 2033498], ["nbclassic", 2033098], ["humming-kernels", 2033075], ["django-cacheops", 2032919], ["textdistance", 2028300], ["ntplib", 2024217], ["opentelemetry-instrumentation-google-generativeai", 2022306], ["django-pglock", 2021743], ["chispa", 2018514], ["mediapipe", 2018388], ["marshmallow-union", 2016058], ["langchain-ollama", 2014249], ["pyramid", 2014188], ["ndindex", 2013294], ["pydata-sphinx-theme", 2012048], ["azure-mgmt-dns", 2010909], ["browserforge", 2010263], ["lsprotocol", 2009960], ["lark-oapi", 2006980], ["pylint-django", 2006882], ["opentelemetry-instrumentation-bedrock", 2005024], ["strawberry-graphql-django", 2004644], ["us", 2003475], ["patito", 2003340], ["easyocr", 1997916], ["impit", 1997188], ["svgwrite", 1995430], ["pillow-avif-plugin", 1994162], ["tree-sitter-scala", 1992445], ["apify-fingerprint-datapoints", 1992316], ["silero-vad", 1990885], ["pyqt5-sip", 1989995], ["pymupdfb", 1983742], ["fasttext", 1982358], ["nvidia-cuda-nvdisasm", 1981422], ["cleanco", 1977664], ["sqlacodegen", 1974926], ["django-scim2", 1973385], ["dash-bootstrap-components", 1970219], ["django-admin-list-filter-dropdown", 1969688], ["dicttoxml", 1967322], ["argparse-addons", 1967083], ["vercel", 1963364], ["pytz-deprecation-shim", 1955496], ["simple-term-menu", 1955158], ["tuspy", 1954443], ["pandas-market-calendars", 1953029], ["opentelemetry-instrumentation-crewai", 1952306], ["scrubadub", 1951787], ["pytest-docker-tools", 1950877], ["uptime-kuma-api", 1948929], ["pywinpty", 1945989], ["sqlalchemy-stubs", 1945578], ["types-tzlocal", 1941438], ["django-safedelete", 1940099], ["pydantic-avro", 1935321], ["pyqt5-qt5", 1934045], ["uncertainties", 1933155], ["avro-gen3", 1931506], ["clr-loader", 1931475], ["azure-mgmt-reservations", 1931165], ["pytorch-metric-learning", 1930728], ["qh3", 1929662], ["mistletoe", 1928084], ["docopt-ng", 1927923], ["opentelemetry-instrumentation-cohere", 1926970], ["findspark", 1924294], ["docusign-esign", 1924132], ["treescope", 1923825], ["strands-agents-tools", 1923737], ["pathlib-mate", 1923296], ["pythonnet", 1922790], ["email-reply-parser", 1918135], ["opentelemetry-instrumentation-qdrant", 1917537], ["plaster", 1916713], ["plaster-pastedeploy", 1916540], ["python-whois", 1914540], ["dogpile-cache", 1914019], ["types-pyasn1", 1911221], ["python-vagrant", 1910760], ["jschema-to-python", 1910054], ["enum-tools", 1909908], ["opentelemetry-instrumentation-llamaindex", 1909747], ["fastsafetensors", 1908873], ["update-checker", 1907252], ["django-admin-inline-paginator", 1904903], ["opentelemetry-instrumentation-ollama", 1903718], ["llama-index-indices-managed-llama-cloud", 1903578], ["agno", 1900581], ["progress", 1896751], ["comfyui-embedded-docs", 1895712], ["google-cloud-recommendations-ai", 1895303], ["opentelemetry-instrumentation-transformers", 1893720], ["secure", 1892685], ["apache-airflow-providers-microsoft-mssql", 1891498], ["opentelemetry-instrumentation-replicate", 1888270], ["opentelemetry-instrumentation-watsonx", 1885612], ["opentelemetry-instrumentation-mistralai", 1883593], ["opentelemetry-instrumentation-together", 1882786], ["opentelemetry-instrumentation-weaviate", 1882350], ["country-converter", 1882290], ["asn1", 1882089], ["crewai-core", 1881548], ["crewai-cli", 1881311], ["simple-parsing", 1881084], ["retry2", 1880408], ["opsgenie-sdk", 1879528], ["opentelemetry-instrumentation-chromadb", 1878823], ["opentelemetry-instrumentation-milvus", 1878298], ["opentelemetry-instrumentation-alephalpha", 1878171], ["evergreen-py", 1876560], ["opentelemetry-instrumentation-pinecone", 1874301], ["pytest-ordering", 1874220], ["dbl-tempo", 1873906], ["opentelemetry-instrumentation-sagemaker", 1873611], ["unleashclient", 1872932], ["llama-index-cli", 1872417], ["comfy-aimdo", 1872204], ["fcache", 1871979], ["oai-statsig-python-core", 1870882], ["dbt-duckdb", 1868047], ["duckdb-engine", 1867597], ["opentelemetry-instrumentation-marqo", 1867474], ["mypy-boto3-ses", 1864147], ["django-rest-polymorphic", 1863785], ["opentelemetry-instrumentation-lancedb", 1863675], ["starlette-context", 1863150], ["opentelemetry-instrumentation-haystack", 1862298], ["columnar", 1861369], ["dbt-redshift", 1858214], ["boostedblob", 1857418], ["django-countries", 1856779], ["crewai-tools", 1854840], ["open-clip-torch", 1854708], ["tantivy", 1851350], ["braintree", 1849449], ["dagster-celery", 1847838], ["nibabel", 1847120], ["openmed", 1847093], ["nvtx", 1846416], ["opencc-python-reimplemented", 1844425], ["readerwriterlock", 1843905], ["crontab", 1843711], ["livekit-plugins-deepgram", 1842872], ["opentelemetry-instrumentation-elasticsearch", 1841902], ["tree-sitter-lua", 1841635], ["immutables", 1841291], ["opentelemetry-instrumentation-mcp", 1841288], ["fpdf", 1841190], ["llama-index-readers-llama-parse", 1841044], ["opentelemetry-instrumentation-groq", 1838694], ["pulumi-gcp", 1837019], ["testing-common-database", 1835859], ["sqltrie", 1834755], ["pep8-naming", 1832557], ["lit", 1832386], ["vercel-oidc", 1830650], ["objsize", 1828928], ["qdldl", 1828887], ["pre-commit-hooks", 1828467], ["pytest-snapshot", 1828039], ["bibtexparser", 1827083], ["nab-index", 1826329], ["tree-sitter-toml", 1823461], ["types-click", 1823375], ["nab-resolver", 1822220], ["mypy-boto3-kinesis", 1822058], ["zxing-cpp", 1820038], ["procrastinate", 1819659], ["s3path", 1819567], ["vercel-headers", 1817715], ["pynvml", 1817581], ["hyperopt", 1816408], ["braintrust-langchain", 1808525], ["traceloop-sdk", 1808104], ["jsonargparse", 1807563], ["pulumi-kubernetes", 1807015], ["cfn-flip", 1804974], ["pytest-watcher", 1804111], ["sqlglotc", 1802468], ["mypy-boto3-logs", 1801665], ["alibabacloud-gateway-spi", 1800838], ["aiodataloader", 1792435], ["application-properties", 1792178], ["python-pam", 1791729], ["scalar-fastapi", 1790402], ["pytest-shard", 1790342], ["tree-sitter-groovy", 1790326], ["pyquaternion", 1787535], ["types-aiobotocore-ec2", 1785665], ["sagemaker-mlflow", 1784565], ["soda-core", 1784242], ["opik", 1784186], ["django-loginas", 1783965], ["linkedin-api-client", 1783307], ["google-search-results", 1782275], ["chdb-core", 1781792], ["kernels", 1779651], ["brotlicffi", 1779647], ["azure-cosmosdb-table", 1779393], ["pyreadline3", 1778551], ["towncrier", 1778461], ["loky", 1778304], ["livekit-plugins-noise-cancellation", 1777953], ["django-postgres-copy", 1773914], ["pyvmomi", 1773141], ["asyncio-atexit", 1772660], ["skl2onnx", 1771221], ["litestar", 1767759], ["xarray-einstats", 1764029], ["pymarkdownlnt", 1763765], ["array-api-compat", 1762178], ["azure-cosmosdb-nspkg", 1760157], ["tables", 1758409], ["vobject", 1758075], ["autograd-gamma", 1757300], ["composio-client", 1756906], ["redisvl", 1756527], ["sqlalchemy-json", 1753613], ["twirp", 1753177], ["posthoganalytics", 1749177], ["kagglesdk", 1748765], ["mleap", 1747374], ["drf-nested-routers", 1746599], ["vl-convert-python", 1742180], ["anysqlite", 1740900], ["google-cloud-recaptcha-enterprise", 1740619], ["nebius", 1740556], ["google-apitools", 1740349], ["crossplane", 1735861], ["pdoc", 1734167], ["connectorx", 1733727], ["hogql-parser", 1733619], ["autocommand", 1730975], ["apache-airflow-providers-sftp", 1730670], ["win32-setctime", 1730321], ["ml-collections", 1727929], ["google-cloud-modelarmor", 1727436], ["opentelemetry-instrumentation-openai-v2", 1727185], ["construct-typing", 1726813], ["dbus-fast", 1726786], ["crowdstrike-falconpy", 1725143], ["django-libsass", 1724343], ["growthbook", 1724089], ["cyclonedx-bom", 1723318], ["model-bakery", 1721925], ["litestar-htmx", 1721677], ["ultralytics-platform", 1719871], ["graphifyy", 1718061], ["triad", 1717658], ["keras-preprocessing", 1715606], ["tree-sitter-objc", 1714942], ["numbers-parser", 1713774], ["pyexcel-io", 1713194], ["alibabacloud-credentials-api", 1712134], ["composio", 1711547], ["iopath", 1711053], ["drf-exceptions-hog", 1710319], ["scikit-base", 1708801], ["sphinx-autobuild", 1708213], ["yt-dlp-ejs", 1707778], ["dvc", 1707292], ["clickhouse-pool", 1707258], ["stpyv8", 1707017], ["openrouter", 1705820], ["language-tags", 1701275], ["kedro", 1700027], ["aiohttp-fast-zlib", 1697804], ["lifelines", 1697563], ["swagger-ui-bundle", 1695481], ["python-memcached", 1695046], ["types-aiobotocore-dynamodb", 1694973], ["types-boto3-sesv2", 1694939], ["pylibsrtp", 1691837], ["mapbox-earcut", 1688450], ["circular-dict", 1688041], ["flask-shell-ipython", 1687634], ["utilsforecast", 1686796], ["statshog", 1686630], ["compact-json", 1686097], ["lml", 1685723], ["tree-sitter-julia", 1683646], ["django-ses", 1682972], ["ddapm-test-agent", 1682718], ["hogql-parser-rs", 1682629], ["zipfile-deflate64", 1682498], ["opentelemetry-propagator-gcp", 1682263], ["aiohttp-jinja2", 1681310], ["pixelhog", 1680421], ["chex", 1680289], ["graphframes", 1678543], ["testing-postgresql", 1676093], ["mitmproxy-wireguard", 1675991], ["aiortc", 1675178], ["deltalite", 1674715], ["tree-sitter-zig", 1673916], ["fugue", 1673810], ["apify-shared", 1673749], ["posthog-hogland", 1673466], ["comtypes", 1672370], ["protoc-gen-openapiv2", 1672209], ["pyramid-mako", 1671421], ["tree-sitter-verilog", 1671082], ["collectfasta", 1671063], ["aioice", 1670955], ["solders", 1669412], ["pytest-sftpserver", 1668903], ["flagsmith-flag-engine", 1665028], ["category-encoders", 1664214], ["logging-azure-rest", 1663899], ["jaro-winkler", 1663814], ["swe-rex", 1663551], ["laspy", 1663308], ["dramatiq", 1663130], ["opentelemetry-instrumentation-openai-agents", 1662740], ["flagsmith", 1661827], ["opentelemetry-instrumentation-openai-agents-v2", 1660763], ["anys", 1660597], ["arize-phoenix-otel", 1660069], ["pystemmer", 1658576], ["properdocs", 1657293], ["mongoengine", 1657125], ["pmdarima", 1656715], ["ulid-py", 1656460], ["gzip-stream", 1655840], ["adagio", 1654761], ["azure-storage-file", 1654580], ["tf-keras", 1653863], ["tink", 1651932], ["tree-sitter-fortran", 1649224], ["pyramid-debugtoolbar", 1647714], ["livekit-plugins-elevenlabs", 1647206], ["docxcompose", 1646385], ["amazon-textract-response-parser", 1644230], ["mido", 1643862], ["envs", 1643532], ["pynput", 1642438], ["python-editor", 1642171], ["tree-sitter-sql", 1640983], ["pyramid-jinja2", 1640923], ["yggdrasil-engine", 1640845], ["boto3-type-annotations", 1639784], ["rust-just", 1639457], ["gssapi", 1636978], ["python-debian", 1636218], ["vercel-internal-telemetry", 1635660], ["py-walk", 1635446], ["django-fernet-fields-v2", 1633410], ["livekit-plugins-cartesia", 1633352], ["teradatasqlalchemy", 1632590], ["vercel-cache", 1632560], ["requests-sigv4", 1631128], ["scmrepo", 1630260], ["application-file-scanner", 1627874], ["types-authlib", 1627317], ["flake8-docstrings", 1626329], ["django-pgmigrate", 1626236], ["deep-translator", 1625523], ["types-networkx", 1625251], ["pyupgrade", 1623957], ["coolprop", 1623664], ["dvc-data", 1623160], ["mdformat-gfm", 1622906], ["pinecone-plugin-assistant", 1621541], ["pypinyin", 1620627], ["ytsaurus-client", 1618885], ["sudachidict-core", 1618883], ["textparser", 1618660], ["aiocsv", 1618275], ["langchain-experimental", 1614684], ["pygls", 1614174], ["google-cloud-scheduler", 1613684], ["types-boto3-iam", 1613339], ["tensorflow-metadata", 1613204], ["qtconsole", 1612776], ["pytest-alembic", 1611204], ["jsonpath-rw", 1610270], ["dvc-objects", 1610145], ["fs", 1608553], ["backports-datetime-fromisoformat", 1608164], ["flask-httpauth", 1606586], ["databricks-vectorsearch", 1604299], ["django-deprecate-fields", 1604182], ["dvc-studio-client", 1603480], ["nab-provider", 1602068], ["pytest-circleci-coverage", 1601755], ["nab-project", 1601576], ["types-aiobotocore-lambda", 1601433], ["stream-python", 1599899], ["pycasbin", 1599580], ["pyreadstat", 1593979], ["fast-depends", 1591628], ["strip-hints", 1589945], ["pyqt6-qt6", 1588120], ["sigfig", 1587890], ["macholib", 1585421], ["opentelemetry-instrumentation-writer", 1583946], ["pycognito", 1582669], ["cloudcruise", 1582662], ["cadquery-ocp", 1581292], ["prefixdate", 1580691], ["dvc-render", 1580654], ["python-liquid", 1578764], ["daft", 1578476], ["django-waffle", 1578156], ["algoliasearch-django", 1577756], ["anybadge", 1576562], ["airportsdata", 1575810], ["cuid", 1574431], ["backports-functools-lru-cache", 1574158], ["jsonalias", 1571565], ["kagglehub", 1571425], ["aiosmtpd", 1566928], ["django-adminplus", 1566749], ["starlette-exporter", 1566549], ["replicate", 1566421], ["dpkt", 1566353], ["ansi2html", 1563980], ["types-dateparser", 1562764], ["lithic", 1562635], ["portion", 1561314], ["dvc-task", 1560846], ["flake8-import-order", 1560821], ["bleak", 1560203], ["dvc-http", 1558279], ["opentelemetry-instrumentation-agno", 1557762], ["pycollada", 1557625], ["fastwarc", 1556440], ["dataclasses-json-speakeasy", 1556280], ["google-cloud-iamconnectorcredentials", 1554567], ["analytics-python", 1552504], ["pysher", 1552079], ["taskgroup", 1550440], ["opentelemetry-instrumentation-voyageai", 1550086], ["acme", 1546335], ["nbstripout", 1545709], ["dagster-dbt", 1545630], ["geocoder", 1545110], ["djangorestframework-role-filters", 1544807], ["pygsheets", 1542843], ["ariadne", 1542750], ["ratelim", 1542474], ["csp-toolkit", 1540023], ["opentelemetry-instrumentation-boto", 1538117], ["mkdocs-macros-plugin", 1537700], ["coreforecast", 1536562], ["pytest-datadir", 1536254], ["mypy-boto3-cloudwatch", 1533807], ["together", 1531537], ["requests-kerberos", 1530927], ["pyvis", 1530886], ["urllib3-future", 1530654], ["owlrl", 1528754], ["keyrings-codeartifact", 1528090], ["ruyaml", 1527761], ["gemmi", 1526141], ["m3u8", 1525714], ["tensorboard-plugin-wit", 1525713], ["apache-airflow-microsoft-fabric-plugin", 1524932], ["jsonnet", 1524753], ["django-taggit", 1522173], ["taskiq-redis", 1521336], ["datefinder", 1517086], ["onnxconverter-common", 1516771], ["jh2", 1516611], ["gto", 1514705], ["polyline", 1513332], ["pyqt6-sip", 1509421], ["mitmproxy-linux", 1508154], ["alibabacloud-tea-util", 1507058], ["flashinfer-cubin", 1506476], ["alphashape", 1505170], ["loongsuite-util-genai", 1504765], ["cadquery-ocp-proxy", 1503598], ["perfetto", 1503496], ["resiliparse", 1502402], ["coredis", 1501711], ["dropbox", 1501065], ["jcs", 1500999], ["mcpo", 1499074], ["lib-detect-testenv", 1498631], ["lazy-model", 1496744], ["taskipy", 1495837], ["tensordict", 1494117], ["super-collections", 1493574], ["graphemeu", 1492064], ["cli-exit-tools", 1490788], ["pyspark-client", 1489561], ["uharfbuzz", 1489205], ["crccheck", 1487987], ["reedsolo", 1487959], ["databricks", 1487740], ["saxonche", 1487485], ["databricks-dlt", 1486463], ["sklearn", 1486020], ["openai-codex-cli-bin", 1484473], ["einx", 1484415], ["mkdocs-monorepo-plugin", 1479064], ["stactools-met-office-deterministic", 1477975], ["dataset", 1477609], ["xgboost-cpu", 1477336], ["beanie", 1476734], ["python-consul", 1475969], ["pyvirtualdisplay", 1475012], ["kedro-datasets", 1473477], ["pyroscope-otel", 1473216], ["argh", 1473170], ["sparsediffpy", 1472651], ["statsforecast", 1472357], ["apache-sedona", 1472332], ["singledispatch", 1471117], ["types-passlib", 1471092], ["azure-mgmt-devtestlabs", 1468043], ["raven", 1467948], ["testpath", 1467767], ["sherpa-onnx", 1466774], ["databento-dbn", 1463649], ["elastic-apm", 1462538], ["geojson-pydantic", 1460674], ["databricks-api", 1460553], ["darabonba-core", 1460514], ["plum-dispatch", 1459827], ["openfga-sdk", 1458110], ["apache-airflow-providers-microsoft-fabric", 1453762], ["qwen-vl-utils", 1452948], ["stone", 1452228], ["array-record", 1451376], ["mypy-boto3-apigateway", 1451345], ["trame-vtk", 1450812], ["flask-sock", 1450707], ["niquests", 1450286], ["mypy-boto3-scheduler", 1448270], ["rerun-sdk", 1447448], ["rfc3161-client", 1446477], ["sudachipy", 1446408], ["protovalidate", 1446037], ["jinja2-ansible-filters", 1445904], ["wassima", 1445528], ["kopf", 1443248], ["brotlipy", 1442975], ["infisicalsdk", 1440411], ["shrub-py", 1439901], ["mongomock-motor", 1435458], ["python-statemachine", 1435424], ["llama-index-multi-modal-llms-openai", 1433944], ["contree-sdk", 1433786], ["types-docker", 1433358], ["pyqt6", 1433142], ["pyexcel", 1433028], ["prometheus-api-client", 1432046], ["nvidia-cublas-cu11", 1431659], ["pyshacl", 1431022], ["astral", 1429486], ["inscriptis", 1427050], ["readability-lxml", 1426058], ["open-webui", 1425276], ["aioredis", 1424205], ["sherpa-onnx-core", 1421217], ["drf-spectacular-sidecar", 1420962], ["prefect-cloud", 1420710], ["scooby", 1420558], ["moreorless", 1420088], ["llama-index-agent-openai", 1417857], ["descope", 1417780], ["sparqlwrapper", 1416610], ["josepy", 1416212], ["azure-containerregistry", 1414744], ["zensical", 1414680], ["dbfread", 1411557], ["sklearn-compat", 1410954], ["sqlitedict", 1410862], ["langchain-postgres", 1410008], ["flask-bcrypt", 1407854], ["py-ubjson", 1407200], ["llama-index-program-openai", 1406695], ["pyvers", 1404680], ["polling", 1404601], ["falcon", 1402902], ["lazy-imports", 1401750], ["copier", 1401058], ["wordninja", 1400582], ["googletrans", 1400301], ["esptool", 1399496], ["nlopt", 1398653], ["wordcloud", 1396671], ["types-xmltodict", 1394181], ["polling2", 1393689], ["c7n", 1393161], ["optimum", 1391543], ["maison", 1391265], ["ibm-cos-sdk", 1390801], ["llama-index-question-gen-openai", 1390490], ["python-chess", 1389835], ["pytensor", 1388923], ["cupy-cuda12x", 1386252], ["dohq-artifactory", 1384521], ["mini-racer", 1384453], ["trame-server", 1381617], ["nvidia-cudnn-cu11", 1380958], ["types-chardet", 1380934], ["python-lsp-jsonrpc", 1380516], ["trailrunner", 1379906], ["androguard", 1377498], ["prime-sandboxes", 1376517], ["wrapt-timeout-decorator", 1375518], ["trame-client", 1374372], ["apsw", 1373671], ["soda-core-spark", 1372711], ["django-admin-rangefilter", 1371009], ["pykerberos", 1370701], ["yara-python", 1370167], ["renderers", 1369724], ["rope", 1369386], ["smartsheet-python-sdk", 1368190], ["apkinspector", 1368083], ["timezonefinder-data", 1366630], ["trame", 1362054], ["databricks-feature-engineering", 1361870], ["ptpython", 1361387], ["param", 1361224], ["camel-converter", 1360927], ["botframework-connector", 1359295], ["mutf8", 1359021], ["types-flask", 1358695], ["json-numpy", 1357924], ["pymodbus", 1357605], ["agentmail", 1357351], ["cma", 1356317], ["splunk-sdk", 1356143], ["botbuilder-schema", 1355470], ["evdev", 1354960], ["contextvars", 1354944], ["jsmin", 1353615], ["contree-client", 1353583], ["icecream", 1353276], ["bm25s", 1352875], ["panel", 1352866], ["sqlakeyset", 1351929], ["ndjson", 1351595], ["pudb", 1350737], ["azure-mgmt-datalake-analytics", 1349232], ["soda-core-spark-df", 1347672], ["randomname", 1346744], ["confusable-homoglyphs", 1346526], ["typeshed-client", 1344297], ["python-jsonpath", 1342776], ["awkward", 1340882], ["wslink", 1340365], ["trame-common", 1340353], ["opentelemetry-instrumentation-aiohttp-server", 1339633], ["pywebview", 1339365], ["seleniumbase", 1338837], ["sqlalchemy-drill", 1338756], ["opencv-contrib-python-headless", 1338539], ["securesystemslib", 1338275], ["openai-codex", 1337703], ["valkey-glide", 1335888], ["proxy-tools", 1335658], ["pymc", 1335615], ["tree-sitter-xml", 1334510], ["html5rdf", 1333760], ["pyre-extensions", 1331817], ["embreex", 1329320], ["keystoneauth1", 1329132], ["app-store-server-library", 1327203], ["fastapi-users", 1326833], ["spython", 1326727], ["interrogate", 1326579], ["customerio", 1325692], ["types-cryptography", 1325273], ["crawl4ai", 1324224], ["langchain-groq", 1324160], ["ephem", 1323884], ["databricks-ai-search", 1323728], ["currency-symbols", 1321205], ["types-python-jose", 1321107], ["python-semantic-release", 1320762], ["colour", 1320738], ["pathy", 1320526], ["django-htmx", 1319306], ["vercel-workers", 1319026], ["mypy-boto3-lakeformation", 1318218], ["stdlibs", 1317784], ["docformatter", 1317649], ["mypy-boto3-xray", 1313839], ["nvidia-cuda-nvcc-cu12", 1312642], ["azure-mgmt-logic", 1311959], ["hatchet-sdk", 1311616], ["aioodbc", 1310904], ["anndata", 1310229], ["psycogreen", 1309148], ["flake8-comprehensions", 1308647], ["django-unfold", 1308131], ["dotmap", 1306748], ["pyannote-metrics", 1304983], ["pyinotify", 1304890], ["flask-marshmallow", 1304246], ["azure-ai-formrecognizer", 1304131], ["west", 1303110], ["sqlalchemy-adapter", 1302653], ["docstring-to-markdown", 1302636], ["pydevd", 1301458], ["trame-vuetify", 1299902], ["azure-schemaregistry", 1299502], ["bump2version", 1299363], ["botbuilder-core", 1299215], ["graphframes-py", 1298635], ["awkward-cpp", 1298195], ["botframework-streaming", 1298124], ["grapheme", 1297125], ["pyannote-core", 1296878], ["imagecodecs", 1296675], ["django-types", 1296643], ["alibabacloud-tea-xml", 1296553], ["krb5", 1295743], ["types-oauthlib", 1295599], ["tuf", 1294936], ["fasttext-numpy2", 1294861], ["msgraphfs", 1294058], ["awsume", 1293827], ["django-auditlog", 1292777], ["pybase62", 1291253], ["deepl", 1290956], ["types-aiobotocore-sts", 1290853], ["lizard", 1290297], ["svgelements", 1288966], ["paddleocr", 1288490], ["outlines", 1288124], ["pytest-pretty", 1287964], ["zhon", 1287935], ["mcp-proxy-for-aws", 1287925], ["pdf2docx", 1287582], ["decord", 1287078], ["kafka-python-ng", 1286552], ["open3d", 1285058], ["httpx-auth", 1284722], ["pyobjc-core", 1283454], ["yamlfix", 1283087], ["pvlib", 1282856], ["pyannote-database", 1281516], ["prime-tunnel", 1281512], ["pybacklogpy", 1280561], ["kylinpy", 1278142], ["cmeel-boost", 1277450], ["opentelemetry-instrumentation-click", 1276263], ["timeago", 1276257], ["bce-python-sdk", 1275074], ["flatdict", 1275071], ["fancycompleter", 1274604], ["pdbpp", 1274258], ["cowsay", 1274143], ["s3cmd", 1273133], ["numpydoc", 1272691], ["mypy-boto3-signer", 1272359], ["aiohttp-client-cache", 1270117], ["mercantile", 1268764], ["torchdata", 1268648], ["whatthepatch", 1268506], ["protoletariat", 1268360], ["model2vec", 1266884], ["faststream", 1265844], ["cmeel", 1265821], ["eigenpy", 1264858], ["cog", 1264729], ["django-widget-tweaks", 1264502], ["prime-pydantic-config", 1264438], ["uszipcode", 1264325], ["mkdocs-redirects", 1264157], ["text2num", 1264051], ["stagehand", 1263652], ["sortedcontainers-stubs", 1262831], ["django-vite", 1260924], ["os-service-types", 1260708], ["objprint", 1260540], ["decopatch", 1260228], ["pin", 1259139], ["milvus-lite", 1258041], ["versioningit", 1256746], ["livekit-plugins-turn-detector", 1256046], ["flask-mail", 1255725], ["ast-grep-py", 1254381], ["kerberos", 1254213], ["flask-restx", 1251698], ["enrich", 1250361], ["robotframework-pythonlibcore", 1247849], ["pylatex", 1247777], ["pydantic-ai-skills", 1247443], ["hanzidentifier", 1245520], ["dkimpy", 1245412], ["types-aiobotocore-secretsmanager", 1245224], ["aiodocker", 1244458], ["jsoncomparison", 1243645], ["pyobjc-framework-cocoa", 1243577], ["pgeocode", 1242751], ["node-semver", 1242518], ["dlinfo", 1241076], ["chonkie", 1240897], ["cmd2", 1238994], ["azure-mgmt-consumption", 1238898], ["flake8-quotes", 1238732], ["scikit-build", 1237173], ["dateutils", 1236832], ["prefect-gcp", 1235404], ["praw", 1235199], ["treelib", 1234569], ["microsoft-agents-activity", 1233467], ["molecule", 1233403], ["kedro-viz", 1232646], ["telnetlib3", 1232402], ["usort", 1232358], ["datasketches", 1231701], ["latexcodec", 1230974], ["nvidia-cuda-runtime-cu11", 1230227], ["pybtex", 1230044], ["azure-mgmt-notificationhubs", 1230038], ["nccl4py", 1229953], ["pubchempy", 1229633], ["pyquery", 1228765], ["py-asciimath", 1228295], ["viztracer", 1227507], ["aiorwlock", 1227452], ["dbt-clickhouse", 1227301], ["git-filter-repo", 1225882], ["mypy-boto3-events", 1225709], ["py-moneyed", 1225599], ["glob2", 1225411], ["python3-xlib", 1225120], ["cmeel-assimp", 1224655], ["solana", 1224487], ["riot", 1223341], ["prawcore", 1222343], ["pytest-flask", 1221886], ["tree-sitter-html", 1220896], ["standard-imghdr", 1220342], ["aaaaaaaaa", 1219214], ["miscreant", 1218668], ["clandestined", 1217911], ["django-pgtrigger", 1216954], ["pysam", 1215380], ["cmeel-urdfdom", 1214304], ["pylibjpeg", 1214178], ["tree-sitter-markdown", 1213871], ["cmeel-zlib", 1213497], ["aws-cdk-asset-kubectl-v20", 1213154], ["synapseml", 1211833], ["tinker", 1211023], ["torchsde", 1210673], ["memoization", 1210235], ["nvidia-cuda-nvrtc-cu11", 1209141], ["pylink-square", 1208655], ["pyexcel-xls", 1208279], ["pulumi-datadog", 1206782], ["azureml-mlflow", 1206427], ["pytest-watch", 1205971], ["pretty-midi", 1205434], ["exchangelib", 1205150], ["zipcodes", 1204393], ["azure", 1204157], ["semantic-link-sempy", 1203358], ["types-boto3-full", 1203337], ["sktime", 1200707], ["lief", 1200485], ["ipy", 1199870], ["testtools", 1198739], ["cmeel-octomap", 1198557], ["dataclasses-avroschema", 1197440], ["roman", 1197070], ["cmeel-qhull", 1197039], ["quantlib", 1196746], ["sasl", 1196442], ["llama-index-embeddings-bedrock", 1195791], ["sphinx-argparse", 1194216], ["psycopg-c", 1193689], ["pyvista", 1192635], ["python-lsp-server", 1192441], ["pylibjpeg-libjpeg", 1191500], ["jwskate", 1190826], ["primepy", 1190541], ["sigstore", 1190343], ["trampoline", 1189960], ["binapy", 1189432], ["ansible-runner", 1188659], ["langchain-tests", 1188067], ["fireworks-ai", 1186607], ["fastapi-users-db-sqlalchemy", 1186256], ["smg-grpc-proto", 1185908], ["openinference-instrumentation-openai-agents", 1185872], ["calver", 1185020], ["pylibjpeg-openjpeg", 1184702], ["pyrender", 1183336], ["microsoft-agents-hosting-core", 1183153], ["beancount", 1182832], ["requests-oauth2client", 1181672], ["diceware", 1180268], ["cmeel-console-bridge", 1179749], ["atlasclient", 1179586], ["apache-airflow-providers-postgres", 1179232], ["graphql-server-core", 1178354], ["ruptures", 1178228], ["zipfile36", 1178018], ["asyncclick", 1177870], ["mypy-boto3-redshift-data", 1177090], ["coremltools", 1176891], ["rtoml", 1176152], ["typesafe-sdk", 1174935], ["sqlalchemy-mate", 1173950], ["stdlib-list", 1173430], ["ocrmypdf", 1171970], ["pytest-flakefinder", 1171345], ["tabula-py", 1171049], ["awsiotsdk", 1170976], ["mozilla-django-oidc", 1170908], ["flask-graphql", 1170742], ["mypy-boto3-codebuild", 1170457], ["shareplum", 1169693], ["impyla", 1168848], ["asteroid-filterbanks", 1167751], ["webdavclient3", 1166332], ["textfsm", 1166170], ["colorcet", 1165568], ["asynciolimiter", 1162843], ["gtts", 1162292], ["sigstore-rekor-types", 1161537], ["pyxdg", 1161121], ["ibm-cos-sdk-core", 1160527], ["neptune-api", 1160100], ["github-copilot-sdk", 1159708], ["pystoi", 1157751], ["cdk-nag", 1157054], ["platformio", 1156545], ["ct3", 1156315], ["sagemaker-schema-inference-artifacts", 1156139], ["ibm-cos-sdk-s3transfer", 1155821], ["azure-ai-contentunderstanding", 1155653], ["llama-index-legacy", 1155360], ["pysnmp", 1154721], ["tensorflow-cpu", 1153988], ["skypilot", 1153697], ["torch-pitch-shift", 1153424], ["django-treebeard", 1153146], ["azure-loganalytics", 1152953], ["connect-python", 1152686], ["neptune-fetcher", 1152343], ["mkdocs-git-revision-date-localized-plugin", 1152246], ["setuptools-download", 1152024], ["django-nested-admin", 1151595], ["colored", 1151529], ["tree-sitter-css", 1151105], ["torch-audiomentations", 1150665], ["modin", 1148215], ["warcio", 1147753], ["ai21", 1146075], ["wand", 1145968], ["ariadne-codegen", 1145884], ["python-monkey-business", 1145734], ["cons", 1144751], ["docker-py", 1144488], ["typesense", 1143902], ["gpustat", 1143884], ["piper-tts", 1143365], ["types-pyserial", 1143290], ["etuples", 1142415], ["pydantic-collections", 1142410], ["minikanren", 1142313], ["svix-ksuid", 1141715], ["google-cloud-parametermanager", 1140471], ["lunardate", 1140192], ["ufmt", 1139350], ["sphinx-tabs", 1139030], ["tensorflow-hub", 1138204], ["logical-unification", 1137075], ["yacs", 1136253], ["robotframework-seleniumlibrary", 1136121], ["sigstore-models", 1136041], ["nab-markersets", 1133517], ["textstat", 1131804], ["pebble", 1130377], ["ably", 1130303], ["pep8", 1130176], ["ldaptor", 1129243], ["sanic", 1128561], ["ajsonrpc", 1127931], ["mypy-boto3-schemas", 1126721], ["cmeel-tinyxml2", 1126704], ["sanic-routing", 1125984], ["langid", 1125748], ["types-confluent-kafka", 1125407], ["wheel-stub", 1125189], ["azure-servicefabric", 1124964], ["measurement", 1124628], ["minify-html", 1124383], ["pyannote-pipeline", 1123834], ["coal", 1122786], ["google-cloud-os-config", 1122410], ["google-cloud-org-policy", 1120996], ["auditwheel", 1120490], ["esprima", 1119881], ["aiogoogle", 1118399], ["azure-mgmt-relay", 1117411], ["svg-path", 1117250], ["cron-validator", 1116739], ["mrml", 1116197], ["pymongocrypt", 1115179], ["akshare", 1115123], ["watchdog-gevent", 1114333], ["boa-str", 1114248], ["robotframework-robocop", 1114069], ["gsutil", 1113389], ["deepspeed", 1113297], ["hmsclient", 1112817], ["mysql-connector", 1111555], ["libusb-package", 1111139], ["codemagic-cli-tools", 1110802], ["pulumi-azure-native", 1110779], ["xenon", 1110393], ["django-json-widget", 1110163], ["fasttext-predict", 1109817], ["yattag", 1109012], ["robotframework-requests", 1108972], ["geohash2", 1108915], ["spglib", 1108876], ["codeguru-profiler-agent", 1108341], ["confuse", 1102433], ["tqdm-loggable", 1102331], ["palettable", 1102077], ["types-aiobotocore-rds", 1101030], ["itypes", 1100788], ["pyaudio", 1099664], ["langchain-litellm", 1098649], ["xattr", 1098246], ["buildkite-sdk", 1097820], ["csscompressor", 1097245], ["proxy-protocol", 1096149], ["airbyte-api", 1095266], ["bson", 1094755], ["fredapi", 1094099], ["pytest-messenger", 1092797], ["html-text", 1092688], ["equinox", 1092530], ["defusedcsv", 1092005], ["aws-cdk-asset-node-proxy-agent-v5", 1091923], ["mlx", 1091194], ["aioapns", 1090379], ["pytoolconfig", 1089835], ["mockito", 1087748], ["intuit-oauth", 1086775], ["flake8-isort", 1086650], ["jinja-partials", 1086067], ["webtest", 1085708], ["azure-mgmt", 1084098], ["json-stream-rs-tokenizer", 1083251], ["django-mptt", 1083200], ["codewords-client", 1082903], ["alpaca-py", 1081406], ["nvidia-cuda-tileiras", 1080959], ["azure-mgmt-powerbiembedded", 1080937], ["warp-lang", 1080847], ["dash-core-components", 1080409], ["simpleitk", 1079886], ["mux-python", 1079808], ["fast-simplification", 1079721], ["lintrunner", 1079596], ["pipecat-ai", 1078789], ["aiomqtt", 1075603], ["ssf", 1075305], ["spandrel", 1074911], ["azure-mgmt-commerce", 1072962], ["pytest-freezer", 1072181], ["azure-mgmt-scheduler", 1071811], ["pulumi-docker", 1070188], ["adbc-driver-postgresql", 1069553], ["aws-lambda-builders", 1068854], ["django-constance", 1067347], ["luqum", 1067326], ["pyjpegls", 1067313], ["imapclient", 1066903], ["pierre-storage", 1066816], ["azure-mgmt-hanaonazure", 1066151], ["openevals", 1065614], ["azure-mgmt-machinelearningcompute", 1065391], ["azure-mgmt-managementpartner", 1065332], ["tree-sitter-regex", 1065138], ["fastapi-login", 1064576], ["titlecase", 1064516], ["fno", 1063969], ["ummalqura", 1063636], ["datacontract-cli", 1063451], ["azure-servicemanagement-legacy", 1063338], ["google-cloud-alloydb-connector", 1062547], ["aws-sam-cli", 1060674], ["azure-mgmt-devspaces", 1059909], ["json-stream", 1059814], ["lm-eval", 1059674], ["pyannote-audio", 1059550], ["dash-html-components", 1059119], ["pact-python", 1059086], ["cadquery", 1058951], ["legacy-api-wrap", 1058663], ["uipath", 1058510], ["xdoctest", 1058151], ["art", 1057590], ["clamd", 1057532], ["spacy-language-detection", 1055645], ["runtype", 1055340], ["sqllineage", 1055091], ["oslo-utils", 1052755], ["liccheck", 1052351], ["azure-applicationinsights", 1050606], ["ase", 1050193], ["asciitree", 1050174], ["open-data-contract-standard", 1049838], ["ragas", 1049565], ["junit2html", 1048010], ["dydantic", 1047952], ["espeakng-loader", 1047652], ["pyspark-huggingface", 1047313], ["dash-table", 1045879], ["standard-sunau", 1045590], ["scikit-network", 1045208], ["google-cloud-access-context-manager", 1045196], ["pycld2", 1044881], ["looseversion", 1043884], ["httpretty", 1042813], ["mypy-boto3-elbv2", 1042676], ["perplexityai", 1042484], ["google-cloud-asset", 1039920], ["opentelemetry-resourcedetector-kubernetes", 1039908], ["pyexasol", 1038835], ["box-sdk-gen", 1037666], ["pytest-anyio", 1037330], ["webrtcvad-wheels", 1037146], ["mkdocs-gen-files", 1036776], ["complexipy", 1036083], ["jsonata-python", 1035849], ["pytest-xprocess", 1035812], ["eccodes", 1034384], ["model-library", 1033888], ["pyudev", 1033074], ["vhacdx", 1032879], ["trustcall", 1032302], ["typos", 1031492], ["torch-geometric", 1031469], ["mkdocs-section-index", 1031222], ["inngest", 1031028], ["requests-auth-aws-sigv4", 1030970], ["fastapi-limiter", 1030806], ["apache-airflow-providers-openlineage", 1030362], ["pyngrok", 1030227], ["pyviz-comms", 1029889], ["pyvisa", 1029274], ["oslo-i18n", 1028776], ["docstring-parser-fork", 1025796], ["shellescape", 1025475], ["mypy-boto3-bedrock", 1024382], ["paypalrestsdk", 1024332], ["extension-helpers", 1024154], ["submitit", 1023829], ["ec2-metadata", 1022748], ["ntc-templates", 1022227], ["pinecone-client", 1021267], ["speechbrain", 1020914], ["virtualenv-clone", 1020514], ["paddlex", 1020356], ["hyperpyyaml", 1020209], ["msgpack-types", 1019739], ["diagrams", 1019631], ["types-aiobotocore-sns", 1019612], ["fast-langdetect", 1018434], ["pretty-html-table", 1018353], ["cloakbrowser", 1018223], ["xls2xlsx", 1017324], ["markdown-exec", 1016656], ["schwifty", 1016137], ["shandy-sqlfmt", 1014771], ["setuptools-git-versioning", 1014662], ["sparkdantic", 1014535], ["lameenc", 1013070], ["spinners", 1012646], ["token-bucket", 1010625], ["coreapi", 1009975], ["smg-grpc-servicer", 1009908], ["bgutil-ytdlp-pot-provider", 1009283], ["modern-treasury", 1007896], ["dnslib", 1006444], ["appworld", 1006294], ["registrable", 1005076], ["requests-oauth", 1004611], ["htmlmin2", 1004250], ["plotext", 1003818], ["j2cli", 1003432], ["pylibjpeg-rle", 1003037], ["localstack-client", 1002933], ["verspec", 1002643], ["mailjet-rest", 1002549], ["robust-downloader", 1002345], ["mypy-boto3-cognito-idp", 1001023], ["path", 1000626], ["scylla-driver", 1000391], ["semantic-link-labs", 1000357], ["pyomo", 1000089], ["openstacksdk", 999837], ["pulumi-docker-build", 999483], ["markdown-to-confluence", 998872], ["datacontract-specification", 998618], ["paypalhttp", 998231], ["mkdocs-glightbox", 996172], ["coreschema", 995561], ["k8s-agent-sandbox", 995430], ["log-symbols", 995225], ["xformers", 994791], ["mdx-truly-sane-lists", 993241], ["fla-core", 992582], ["jsonpath", 991837], ["unsloth-zoo", 991755], ["bump-my-version", 991513], ["tecton", 990825], ["git-remote-codecommit", 986568], ["agent-framework-core", 986100], ["aistudio-sdk", 985973], ["businesstimedelta", 985938], ["delta-sharing", 985920], ["traceback2", 985105], ["oslo-config", 983060], ["linecache2", 982869], ["objgraph", 982347], ["flameprof", 982297], ["comfyui-workflow-templates-media-video", 981412], ["django-htmlmin", 981379], ["svgpathtools", 980903], ["django-picklefield", 980753], ["workalendar", 980678], ["ziglang", 980319], ["debtcollector", 979826], ["sparse", 979762], ["inspect-swe", 979535], ["ddt", 979078], ["paypal-checkout-serversdk", 978561], ["comfyui-workflow-templates-media-other", 977589], ["naked", 977489], ["ocspbuilder", 977435], ["asyncache", 977268], ["schematics", 977268], ["pyswisseph", 977093], ["nothing", 976813], ["livekit-plugins-anthropic", 976605], ["whoosh", 976405], ["ocspresponder", 976402], ["databento", 976078], ["comfyui-workflow-templates-media-image", 974697], ["wmill", 973910], ["returns", 973877], ["recordlinkage", 973574], ["authzed", 973255], ["opentelemetry-resourcedetector-docker", 973082], ["paddlepaddle", 972707], ["rlpycairo", 972376], ["pymp4", 972312], ["numpyro", 972250], ["python-schema-registry-client", 971747], ["typing-utils", 971332], ["pyserde", 970672], ["comfyui-workflow-templates-media-api", 970563], ["pyvips", 969164], ["stockfish", 968026], ["pysrt", 966874], ["alibabacloud-openapi-util", 966275], ["htmldocx", 965632], ["luigi", 965483], ["evergreen-lint", 965331], ["abnf", 965193], ["insightface", 965037], ["cantools", 964867], ["mohawk", 964702], ["pytest-cache", 964435], ["shyaml", 964297], ["unsloth", 964173], ["dagster-pandas", 964140], ["pylint-pydantic", 964002], ["types-shapely", 962518], ["arch", 961444], ["itables", 960766], ["curatorbin", 960259], ["redis-entraid", 959833], ["jinja2-cli", 959477], ["airtable", 959332], ["annoy", 958831], ["stream-zip", 958438], ["mcp-for-blender", 957351], ["types-aiobotocore-cloudformation", 957034], ["netmiko", 956909], ["openvino-telemetry", 956448], ["sunshine-conversations-client", 956104], ["amazon-textract-caller", 955617], ["arize-phoenix-client", 955361], ["unpaddedbase64", 955179], ["asyncmy", 954029], ["gym", 953386], ["fastapi-cache2", 953013], ["pymap3d", 952509], ["typish", 952299], ["vertexai", 951221], ["googleads", 951144], ["adyen", 950996], ["fluent-syntax", 950830], ["cbor", 950108], ["tensorflow-addons", 949754], ["urlextract", 949639], ["trame-components", 949241], ["graphene-django", 949091], ["pact-python-ffi", 948397], ["cliff", 948283], ["libpinocchio", 948262], ["pypsrp", 947742], ["visitor", 947240], ["session-info2", 946805], ["mike", 946316], ["types-decorator", 945923], ["plac", 944967], ["pem", 944669], ["creosote", 944544], ["mosaicml-streaming", 943789], ["syllapy", 943049], ["hera", 942545], ["libcoal", 942292], ["flask-bootstrap", 940527], ["mypy-boto3-appflow", 940197], ["json2html", 939341], ["habluetooth", 939334], ["django-localflavor", 938496], ["agnoctl", 937427], ["strict-rfc3339", 935953], ["django-tenants", 935639], ["pybytebuffer", 934011], ["comfyui-workflow-templates-media-assets-02", 933842], ["openvino", 933810], ["elementary-data", 932978], ["findlibs", 932582], ["dagster-rest-resources", 932030], ["srt", 930712], ["scenedetect", 930636], ["hindsight-client", 929373], ["stomp-py", 928876], ["nicegui", 927571], ["skillsaw", 927423], ["stream-inflate", 927291], ["pyrepl", 927058], ["www-authenticate", 926924], ["vit-pytorch", 926255], ["sqladmin", 926060], ["apache-airflow-providers-apache-kafka", 924717], ["inspect-evals", 923317], ["kconfiglib", 923221], ["ta", 923074], ["influxdb3-python", 922074], ["fake-http-header", 921905], ["cython-lint", 921328], ["squawk-cli", 921310], ["oci-cli", 920828], ["pgserver", 920250], ["stream-unzip", 920142], ["austin-dist", 919623], ["eralchemy", 918918], ["dj-rest-auth", 918207], ["knockapi", 917183], ["source-distribution", 917155], ["pyodps", 916213], ["pytrends", 915091], ["tf-playwright-stealth", 914919], ["bsdiff4", 914662], ["akeyless", 914644], ["dagster-gcp", 914100], ["selinux", 913183], ["oslo-serialization", 912259], ["hidapi", 911312], ["chargebee", 911291], ["boto3-stubs-full", 911207], ["buildkite-test-collector", 910421], ["pyenchant", 909980], ["mergepythonclient", 909742], ["types-sqlalchemy-utils", 909711], ["types-aiobotocore-bedrock-runtime", 909698], ["assertpy", 908864], ["cdk-ecr-deployment", 908336], ["qpsolvers", 908053], ["sqlite-utils", 907846], ["okta", 907605], ["autopage", 907386], ["clang", 907254], ["amazon-textract-textractor", 906079], ["dodgy", 904497], ["django-allow-cidr", 904199], ["django-guardian", 904021], ["py3dbp", 903553], ["safe-pysha3", 903503], ["azure-appconfiguration-provider", 902649], ["langchain-huggingface", 902514], ["datafusion", 902224], ["pixelmatch", 902120], ["scrapling", 901847], ["types-boto", 900677], ["requests-pkcs12", 899796], ["kernels-data", 899610], ["uipath-langchain", 899075], ["wurlitzer", 898886], ["orb-billing", 898306], ["lob", 896928], ["livekit-plugins-google", 896049], ["agent-sanitizer", 895995], ["vadersentiment", 895878], ["pylev", 894834], ["sqlite-fts4", 894287], ["waybackpy", 894114], ["iterfzf", 893695], ["libvalkey", 893249], ["pyroute2", 893228], ["jupyter-ydoc", 892302], ["azure-ai-contentsafety", 891442], ["rfc3339", 891396], ["cascadio", 891311], ["postmarker", 890790], ["mypy-boto3-batch", 890699], ["csvw", 890278], ["crawlee", 889071], ["rollbar", 888788], ["coveralls", 888646], ["confusables", 888602], ["domdf-python-tools", 888394], ["pytest-testinfra", 888071], ["fastcrc", 887849], ["comfy-angle", 887389], ["tensorflow-probability", 886901], ["cerebras-cloud-sdk", 885489], ["pygraphviz", 885192], ["py-money", 884499], ["importlab", 884426], ["types-reportlab", 884172], ["fastf1", 883251], ["unicorn", 882756], ["pulsar-client", 882081], ["python-gdcm", 881512], ["pytest-qt", 881114], ["prisma", 880585], ["dvc-s3", 880448], ["monai", 88e4], ["telesign", 879422], ["pynvvideocodec", 877800], ["databricks-bundles", 877748], ["ipympl", 877681], ["tentaclio", 876742], ["telesignenterprise", 876690], ["unitycatalog-client", 874257], ["pytest-race", 873972], ["geonamescache", 873427], ["pymeta3", 873095], ["supervision", 872530], ["segments", 871184], ["flash-attn-4", 870839], ["gspread-formatting", 870108], ["splink", 869894], ["pluginbase", 869602], ["typst", 869420], ["eradicate", 869134], ["rpyc", 868486], ["drawsvg", 868052], ["pynetbox", 867962], ["guppy3", 867191], ["prefect-docker", 867106], ["mcp-proxy", 867062], ["readabilipy", 866702], ["microsoft-agents-authentication-msal", 865795], ["cartopy", 864908], ["leidenalg", 864344], ["cvxopt", 864222], ["aerospike", 864069], ["geckodriver-autoinstaller", 863028], ["verifiers", 862722], ["langchain-chroma", 862236], ["pytype", 861792], ["apache-airflow-providers-microsoft-azure", 861350], ["upstash-redis", 861006], ["pyxirr", 860543], ["argparse-dataclass", 860430], ["gitlint-core", 859987], ["mlx-metal", 859938], ["wikipedia", 859719], ["ahocorasick-rs", 859677], ["envyaml", 859554], ["starlette-compress", 859470], ["shelved-cache", 859014], ["nbsphinx", 858813], ["pulumi-awsx", 858772], ["evidently", 858313], ["plyfile", 858136], ["authy", 857957], ["pyandoc", 857549], ["pycnite", 857517], ["edgartools", 857191], ["sigtools", 856948], ["flake8-print", 855998], ["viser", 855523], ["sagemaker-serve", 855371], ["wbdata", 855032], ["biotite", 855026], ["hdijupyterutils", 854656], ["autovizwidget", 854486], ["pedalboard", 853933], ["crispy-bootstrap5", 853705], ["pytest-picked", 853427], ["lap", 852501], ["types-emoji", 851606], ["prefect-github", 849381], ["databricks-ai-bridge", 849282], ["fickling", 848699], ["tableau-api-lib", 848367], ["vegafusion", 848006], ["py-grpc-prometheus", 847886], ["tentaclio-s3", 847729], ["pandoc", 847471], ["sagemaker-mlops", 847451], ["msgpack-numpy", 847430], ["troposphere", 846851], ["jupyter-server-ydoc", 846335], ["dropbox-sign", 846262], ["fastapi-utils", 845948], ["yarg", 844900], ["patool", 844510], ["nab", 843950], ["chalk-viztracer", 843540], ["langchain-openrouter", 843181], ["artifacts-keyring", 843066], ["mgrs", 842839], ["pyvespa", 842419], ["jsonmerge", 842417], ["yandexcloud", 842263], ["python-redis-lock", 841769], ["django-tables2", 841082], ["fast-diff-match-patch", 840903], ["ydb", 840786], ["jupyter-server-fileid", 840467], ["esp-pylib", 840255], ["uproot", 840201], ["eccodeslib", 839523], ["langchain-mistralai", 839175], ["pywinauto", 839021], ["pysmi", 838489], ["pytest-regressions", 838432], ["flask-smorest", 838372], ["eckitlib", 837931], ["pystray", 837896], ["descript-audiotools", 837112], ["sudachidict-full", 835131], ["pyocd", 833784], ["django-colorfield", 833315], ["sphinx-click", 832952], ["qiskit", 832565], ["dishka", 829953], ["halo", 829755], ["pytelegrambotapi", 829421], ["htmlmin", 829374], ["msgpack-python", 828911], ["sagemaker-train", 828299], ["mkdocs-mermaid2-plugin", 828189], ["livekit-plugins-assemblyai", 827785], ["google-cloud-video-transcoder", 827261], ["ecos", 827250], ["mdformat-frontmatter", 827096], ["django-webpack-loader", 826101], ["reportportal-client", 826097], ["pyawscron", 825692], ["pytest-freezegun", 825279], ["pipedream", 824926], ["pyexcel-xlsx", 824428], ["libtpu", 824078], ["xlsx2csv", 823202], ["plotly-express", 822679], ["kr8s", 822303], ["rawpy", 821141], ["emails", 820750], ["pyvisa-py", 820484], ["grain", 820349], ["cmsis-pack-manager", 820259], ["izulu", 819962], ["mediapy", 818610], ["pygltflib", 818198], ["publish-event-sns", 818018], ["anyscale", 817813], ["langgraph-checkpoint-redis", 816421], ["collections-extended", 816138], ["weave", 816001], ["logzio-python-handler", 815985], ["sgp4", 815785], ["dockerpty", 815667], ["types-aiobotocore-ecr", 815639], ["taskcluster", 815315], ["mkdocs-literate-nav", 815099], ["imutils", 814987], ["apache-airflow-providers-odbc", 814706], ["azure-mgmt-redisenterprise", 814490], ["dingtalk-stream", 814309], ["oso-cloud", 813825], ["tableauhyperapi", 813316], ["gputil", 812361], ["pyasyncore", 812354], ["polyfile-weave", 812088], ["mailchimp-transactional", 811564], ["yoyo-migrations", 811431], ["flasgger", 810900], ["cint", 810367], ["gdbmongo", 809868], ["databricks-labs-remorph", 809536], ["pydoclint", 808694], ["daytona-sdk", 808619], ["pyshark", 808514], ["scikit-rf", 807611], ["flask-debugtoolbar", 807036], ["pytest-cases", 806776], ["dbt-athena", 805588], ["darglint", 805217], ["utm", 805181], ["idf-component-manager", 804805], ["python-qpid-proton", 802929], ["pyfarmhash", 802837], ["gviz-api", 802772], ["sharepy", 802358], ["trustme", 802188], ["json-e", 802152], ["mypy-boto3-textract", 800918], ["recommonmark", 800875], ["mypy-baseline", 800715], ["aiosonic", 800595], ["openapi-schema-pydantic", 799392], ["systemrdl-compiler", 799389], ["lkml", 799341], ["psmpy", 799156], ["cem", 799101], ["pybind11-stubgen", 798717], ["pulumi-postgresql", 798715], ["types-botocore", 797532], ["causallib", 797130], ["argbind", 796838], ["langchain-mongodb", 796474], ["html5tagger", 796176], ["pycarlo", 796066], ["pyicumessageformat", 795851], ["rpmfile", 795764], ["price-parser", 795595], ["hl7apy", 795302], ["visions", 795242], ["jaraco-collections", 795090], ["taskcluster-urls", 794740], ["logzero", 794139], ["pinotdb", 793983], ["match", 793190], ["zthreading", 793100], ["idna-ssl", 792788], ["nvshmem4py-cu13", 792357], ["crc", 791337], ["retryhttp", 791013], ["xlutils", 790630], ["google-cloud-error-reporting", 790578], ["pyobjc-framework-quartz", 790294], ["holoviews", 790033], ["davey", 788898], ["pymatgen", 788185], ["onecache", 787021], ["hsluv", 786364], ["vispy", 786124], ["textual-serve", 785189], ["reporters-db", 785083], ["lean-lsp-mcp", 784384], ["leanclient", 784099], ["pandas-flavor", 783983], ["openinference-instrumentation-claude-agent-sdk", 783895], ["avro-gen", 783277], ["jsons", 782911], ["stix2-patterns", 782590], ["redo", 781628], ["sshpubkeys", 781254], ["darkdetect", 779922], ["trafaret", 779682], ["pynose", 779291], ["feu", 778713], ["django-modeltranslation", 778351], ["python-quickbooks", 777846], ["suds-py3", 777760], ["config", 776834], ["unittest2", 776737], ["cedarpy", 776202], ["pytrec-eval-terrier", 775782], ["courts-db", 775750], ["pytest-test-groups", 775731], ["ntlm-auth", 775673], ["types-stripe", 775636], ["validate-email", 775519], ["boost-histogram", 774852], ["lintrunner-adapters", 774762], ["monty", 774759], ["openinference-instrumentation-anthropic", 774514], ["patch", 774372], ["pyftpdlib", 774013], ["unclecode-litellm", 773739], ["aws-assume-role-lib", 773683], ["zen-engine", 773390], ["google-auth-stubs", 772424], ["parsley", 771824], ["hologram", 771772], ["sphinxcontrib-httpdomain", 771767], ["panzi-json-logic", 771756], ["chz", 771146], ["shopifyapi", 771031], ["nvidia-cusparse-cu11", 770854], ["omnibase-core", 770702], ["stable-baselines3", 770213], ["locust-cloud", 770174], ["nvidia-cufft-cu11", 770103], ["slugid", 769961], ["nvidia-cusolver-cu11", 769363], ["breathe", 768786], ["httpx-oauth", 768776], ["adjusttext", 768177], ["asyncua", 768068], ["tonyg-rfc3339", 767981], ["pylint-per-file-ignores", 767801], ["flake8-noqa", 767733], ["eyecite", 767532], ["mkdocs-awesome-nav", 766645], ["camoufox", 766265], ["django-rq", 764660], ["flake8-polyfill", 764470], ["nvidia-curand-cu11", 763319], ["panel-material-ui", 762689], ["coacd", 762502], ["urwid-readline", 762497], ["tracerite", 762110], ["flash-linear-attention", 762068], ["petl", 760848], ["awscli-local", 760808], ["ncclient", 760193], ["stanza", 760145], ["fastapi-mail", 759756], ["cachetools-async", 759688], ["scanpy", 759030], ["pdf-inspector", 759022], ["sendsafely", 758527], ["python-subunit", 758499], ["nvidia-cuda-cupti-cu11", 757863], ["camelot-py", 757496], ["usd-core", 757390], ["morecantile", 757134], ["datadog-checks-base", 757123], ["mypy-boto3", 756841], ["clearml", 756689], ["rocksdict", 756628], ["bigquery-schema-generator", 756212], ["throttler", 755940], ["python-keystoneclient", 755671], ["apache-airflow-providers-pagerduty", 755362], ["queries", 753860], ["linq-python", 753511], ["pyactiveresource", 752844], ["mslex", 752686], ["ruamel-yaml-jinja2", 752605], ["gym-notices", 752254], ["python-fsutil", 752093], ["traittypes", 751648], ["google-geo-type", 751298], ["fvcore", 751267], ["jsonfield", 750675], ["django-rest-knox", 750367], ["onnxslim", 750232], ["azure-multiapi-storage", 750089], ["y-py", 749809], ["mkdocs-minify-plugin", 749746], ["langmem", 749440], ["adbutils", 749438], ["nvidia-nvtx-cu11", 748654], ["foxglove-schemas-protobuf", 748533], ["lmfit", 748094], ["s5cmd", 747018], ["types-factory-boy", 746794], ["opentelemetry-instrumentation-litellm", 746565], ["gender-guesser", 745952], ["databases", 745806], ["brotli-asgi", 745715], ["pre-commit-uv", 745314], ["docker-compose", 744420], ["asammdf", 743866], ["hexdump", 743620], ["gurobipy", 743448], ["langchain-xai", 743390], ["skia-python", 742716], ["metaphone", 741561], ["stix2", 740429], ["django-cte", 740402], ["flask-openid", 740267], ["firecrawl", 740037], ["meshio", 739923], ["baml-py", 738715], ["pika-stubs", 738480], ["actionlint-py", 738255], ["fugashi", 737971], ["rauth", 737464], ["rioxarray", 736973], ["advanced-alchemy", 735800], ["sshconf", 735723], ["mcp-grafana", 735673], ["pygdbmi", 735555], ["torch-memory-saver", 735160], ["purecloudplatformclientv2", 734860], ["ps-mem", 733866], ["types-termcolor", 733113], ["pytest-reportlog", 732982], ["pyproject-fmt", 732803], ["py-mini-racer", 732528], ["clikit", 732044], ["nvidia-mathdx", 731849], ["pyqtgraph", 731736], ["blingfire", 731090], ["nvidia-nccl-cu11", 730287], ["gpytorch", 729987], ["sglang-kernel", 729790], ["jinja2-time", 729586], ["phonemizer", 728807], ["delta-kernel-rust-sharing-wrapper", 727896], ["sec-api", 726786], ["pygobject", 726590], ["hmmlearn", 726437], ["ibmmq", 725789], ["mecab-python3", 725744], ["sphinx-book-theme", 725356], ["transliterate", 724968], ["mcap-protobuf-support", 724652], ["pycapnp", 724610], ["molecule-plugins", 724397], ["sox", 724380], ["plantuml-markdown", 724322], ["uroman", 724203], ["jinjanator", 723690], ["jstyleson", 722829], ["first", 722372], ["klayout", 721762], ["linear-operator", 721414], ["backports-weakref", 721208], ["vimgolf", 720326], ["pytest-flake8", 720218], ["arize-phoenix-evals", 720202], ["mnemonic", 720089], ["gidgethub", 719665], ["tool", 719443], ["spark-nlp", 719217], ["types-enum34", 718716], ["isolate", 718140], ["sphinx-reredirects", 718112], ["falkordb", 717981], ["smartlingapisdk", 717924], ["rich-text-renderer", 717577], ["taskcluster-taskgraph", 717464], ["iso4217", 717365], ["empy", 717106], ["pyjsparser", 716675], ["pytest-nunit", 716350], ["paste", 716322], ["mypy-boto3-route53", 716107], ["scverse-misc", 715934], ["gliner", 715672], ["openinference-instrumentation-litellm", 715417], ["emcee", 714176], ["pytorch-tokenizers", 713948], ["subprocess32", 713849], ["django-money", 712764], ["find-libpython", 712717], ["jinjanator-plugins", 712449], ["azureml-featurestore", 712395], ["streamlit-aggrid", 711588], ["google-cloud-jupyter-config", 711105], ["types-aiobotocore-ssm", 709640], ["splunk-handler", 709607], ["usearch", 709600], ["django-coverage-plugin", 709020], ["ifcopenshell", 708936], ["mcp-atlassian", 708315], ["rumdl", 707912], ["pypiwin32", 707597], ["mypy-boto3-eks", 707532], ["cartesia", 707344], ["swig", 707284], ["salt-lint", 707185], ["apache-airflow-providers-jdbc", 706762], ["google-cloud-dialogflow-cx", 706065], ["pyasynchat", 705720], ["simplekml", 705666], ["htmltools", 705482], ["phik", 704717], ["mypy-boto3-autoscaling", 704316], ["apipkg", 703973], ["django-log-request-id", 703791], ["crypto", 703084], ["unitycatalog-ai", 702736], ["pyqrcode", 701046], ["apache-airflow-providers-celery", 700211], ["rouge", 700130], ["flask-swagger-ui", 700094], ["django-multiselectfield", 699652], ["mteb", 699326], ["yourdfpy", 698241], ["click-help-colors", 698130], ["sphinx-autoapi", 697390], ["backports-tempfile", 697159], ["tensorflow-datasets", 697084], ["langchain-qdrant", 696569], ["betterproto2", 696561], ["alibabacloud-gateway-dingtalk", 695749], ["apache-airflow-providers-mongo", 695134], ["canmatrix", 694448], ["pydeprecate", 694295], ["tempora", 693933], ["telnyx", 693128], ["lpips", 692515], ["jsonpath-rust-bindings", 692334], ["mkdocs-click", 691167], ["magiccube", 691163], ["django-autocomplete-light", 690833], ["homeassistant", 690298], ["openapi-generator-cli", 690121], ["apache-airflow-providers-docker", 689367], ["xmljson", 689199], ["ydata-profiling", 689196], ["flask-testing", 689069], ["httmock", 688003], ["bedrock-agentcore-starter-toolkit", 687776], ["pympp", 687627], ["py-openapi-schema-to-json-schema", 687457], ["codecov", 686589], ["snowflake-cli", 686588], ["ibm-platform-services", 686541], ["djangorestframework-camel-case", 685781], ["arize-phoenix", 685441], ["mkdocs-awesome-pages-plugin", 685255], ["apache-libcloud", 685137], ["pysimdjson", 685093], ["amazon-transcribe", 684912], ["azureml-core", 684832], ["fastprogress", 684678], ["google-play-scraper", 684575], ["reuse", 684016], ["mkdocs-panzoom-plugin", 683952], ["draccus", 683460], ["mlxtend", 682747], ["pystan", 682358], ["fastrlock", 681689], ["manhole", 681525], ["moderngl", 681523], ["fnvhash", 681225], ["ua-generator", 680896], ["databricks-mcp", 680740], ["elasticsearch-dbapi", 680502], ["bumpversion", 679686], ["smbus2", 679682], ["pulumi-aws-native", 679637], ["edgegrid-python", 679633], ["marshmallow-jsonschema", 679003], ["ping3", 678598], ["regexploit", 678511], ["s3pathlib", 678072], ["hist", 678022], ["pyannoteai-sdk", 677376], ["tzwhere", 677360], ["cut-cross-entropy", 676851], ["blessings", 676644], ["scrapbook", 676550], ["ypy-websocket", 675690], ["mypy-boto3-sesv2", 675514], ["remote-pdb", 675318], ["cashews", 675163], ["g711", 674970], ["demjson3", 674969], ["apache-airflow-providers-datadog", 674737], ["number-parser", 674590], ["glcontext", 674212], ["robotframework-browser", 674087], ["cmakelang", 673045], ["pytest-insta", 672713], ["catkin-pkg", 672385], ["python-geohash", 671953], ["ydb-dbapi", 671910], ["canopen", 671249], ["func-args", 671157], ["uiautomator2", 671111], ["simplegeneric", 670755], ["plato-sdk-v2", 670753], ["systemd-python", 670289], ["opentelemetry-resourcedetector-process", 670250], ["pythainlp", 670140], ["opentelemetry-container-distro", 669415], ["razorpay", 669213], ["azure-schemaregistry-avroserializer", 668999], ["flask-dance", 668572], ["flake8-eradicate", 668569], ["data-designer", 668478], ["xopen", 668176], ["snakemake-interface-common", 668060], ["data-designer-config", 667830], ["webflow", 667437], ["graphene-pydantic", 667431], ["types-futures", 667350], ["types-aiobotocore-cognito-idp", 667273], ["cfgrib", 667180], ["data-designer-engine", 667128], ["pulumi-cloudflare", 666864], ["cloudwatch", 666724], ["openinference-instrumentation-google-genai", 666596], ["snakemake-interface-storage-plugins", 665278], ["gtfs-realtime-bindings", 664996], ["python-logging-loki", 664398], ["cmaes", 664383], ["boto-session-manager", 663280], ["descript-audio-codec", 662556], ["pytest-reportportal", 662355], ["httpr", 662222], ["locust-plugins", 661908], ["sphinxcontrib-plantuml", 661893], ["openexr", 661835], ["types-aiobotocore-kms", 661834], ["dicom2nifti", 661746], ["blender-mcp", 661744], ["matrix-nio", 661030], ["uhashring", 660841], ["cuid2", 660808], ["mozilla-taskgraph", 660737], ["xlwings", 660622], ["tls-client", 660428], ["isolate-proto", 659317], ["pyseccomp", 658785], ["stytch", 657547], ["unidic-lite", 657342], ["asyncinotify", 657064], ["hunter", 657050], ["httpxthrottlecache", 656386], ["psd-tools", 656150], ["flake8-plugin-utils", 655962], ["agent-framework-openai", 654825], ["codetiming", 654496], ["cadquery-ocp-novtk", 653999], ["pymavlink", 653641], ["iterproxy", 653323], ["types-jmespath", 652433], ["imap-tools", 651700], ["test-results-parser", 651134], ["django-browser-reload", 650878], ["fhirpy", 649912], ["apeye-core", 649705], ["graphene-sqlalchemy", 649458], ["pipreqs", 648631], ["numpy-quaternion", 648272], ["codecov-cli", 647770], ["unstructured-pytesseract", 647178], ["metronome-sdk", 646593], ["py-markdown-table", 645656], ["azure-functions-durable", 645500], ["dracopy", 644912], ["openinference-instrumentation-agno", 644352], ["python-benedict", 644059], ["sqlalchemy-continuum", 643929], ["flake8-broken-line", 643543], ["django-ckeditor", 643423], ["aioconsole", 643128], ["openhands-agent-server", 642725], ["foundry-platform-sdk", 641622], ["torchdiffeq", 641569], ["azure-mgmt-hybridcompute", 641484], ["imgtool", 641412], ["esp-idf-kconfig", 641123], ["mozilla-repo-urls", 640515], ["odxtools", 640451], ["fsspec-xrootd", 639827], ["interpret-core", 639266], ["pyecharts", 639066], ["json-logging", 638052], ["google-python-cloud-debugger", 637755], ["nuitka", 637679], ["intel-openmp", 636845], ["ngrok", 636818], ["tencentcloud-sdk-python-common", 636779], ["ldapdomaindump", 636666], ["django-dirtyfields", 636311], ["pymongo-search-utils", 634944], ["boto3-stubs-lite", 634890], ["pyro-api", 634688], ["logging", 634534], ["frictionless", 634247], ["openwakeword", 633907], ["langchain-deepseek", 633827], ["dictor", 633367], ["singleton-decorator", 633295], ["runpod", 633035], ["cloup", 632823], ["snakebite-py3", 632812], ["pyro-ppl", 632706], ["frida", 632387], ["graphiti-core", 632384], ["libpass", 631344], ["covdefaults", 631158], ["partialjson", 630565], ["impacket", 629726], ["newrelic-telemetry-sdk", 629683], ["mypy-boto3-sagemaker", 629318], ["google-cloud-bigquery-biglake", 629237], ["ta-lib", 628613], ["icmplib", 628451], ["pyslang", 628429], ["fiddle", 628339], ["wonderwords", 628025], ["unstructured-inference", 627759], ["miniaudio", 627452], ["httpstan", 627046], ["chronos-forecasting", 626638], ["pdbp", 626544], ["iregexp-check", 626470], ["draftjs-exporter", 626370], ["retell-sdk", 625959], ["customtkinter", 625635], ["rosbags", 625614], ["mpi4py", 625283], ["django-mysql", 624659], ["typed-settings", 623384], ["rangehttpserver", 623283], ["tensorlake", 623075], ["types-aiobotocore-cloudwatch", 621989], ["mypy-boto3-firehose", 621946], ["meilisearch", 621712], ["kaggle", 621702], ["jpholiday", 621474], ["vercel-internal-core", 620850], ["facexlib", 620741], ["onfido-python", 620442], ["dash-ag-grid", 619711], ["jsonpath-rfc9535", 619701], ["django-pghistory", 619527], ["jplephem", 619519], ["sccache", 619163], ["hnswlib", 618827], ["poly-eip712-structs", 618743], ["lomond", 618389], ["types-boto3-kms", 618021], ["inflector", 617671], ["distance", 617643], ["torch-stoi", 616971], ["githubkit", 616829], ["scons", 616781], ["johnnydep", 616570], ["airbyte-cdk", 616025], ["jsoncompat", 615665], ["jupyter-cache", 615655], ["py-order-utils", 615539], ["lazrs", 615485], ["wimpy", 615294], ["mf2py", 615071], ["simple-azure-blob-downloader", 614716], ["casbin-sqlalchemy-adapter", 614618], ["flake8-bandit", 614595], ["mypy-boto3-organizations", 614577], ["httpie", 614531], ["snac", 614067], ["tabcompleter", 613920], ["gevent-websocket", 613913], ["markuppy", 613878], ["sftpserver", 613681], ["bingads", 613670], ["mongo-orchestration", 613257], ["fairscale", 613176], ["django-tasks", 613009], ["eventkit", 612778], ["streamlit-autorefresh", 612733], ["langchain-tavily", 612631], ["onnxmltools", 612373], ["ocpsvg", 612227], ["exifread", 612033], ["arize", 612010], ["ibm-watsonx-ai", 612001], ["pytest-opentelemetry", 611269], ["traia-iatp", 610297], ["lib3mf", 609692], ["grep-ast", 609429], ["easyprocess", 609006], ["asn1tools", 608847], ["pymoo", 608696], ["hatchling-autoextras-hook", 608491], ["cos-python-sdk-v5", 608222], ["pydevd-pycharm", 608140], ["dict2xml", 608030], ["pyppeteer", 607982], ["mapbox-vector-tile", 607468], ["gitlint", 607447], ["purgatory", 607311], ["libusb1", 607169], ["moocore", 606618], ["vosk", 606604], ["peppercorn", 606597], ["soniox", 606368], ["hl7", 606357], ["diskcache-weave", 605744], ["pysqlite3-binary", 605684], ["wagtail", 605647], ["types-pexpect", 605345], ["sphinxext-opengraph", 605258], ["countryinfo", 605032], ["pytest-azurepipelines", 604615], ["akracer", 604299], ["ocp-gordon", 603807], ["myst-nb", 603729], ["trianglesolver", 603643], ["traceback-with-variables", 603515], ["dukpy", 603314], ["mkdocs-techdocs-core", 603227], ["textwrap3", 602938], ["cerberus-python-client", 602921], ["faust-cchardet", 602480], ["extruct", 602391], ["esp-coredump", 602365], ["petname", 601650], ["aws-cryptographic-material-providers", 601581], ["filesplit", 601570], ["flask-oidc", 601504], ["aws-cryptography-internal-dynamodb", 601122], ["robotspy", 601088], ["aws-cryptography-internal-standard-library", 601001], ["meraki", 600893], ["aws-cryptography-internal-primitives", 600812], ["fixedwidth", 600796], ["aws-cryptography-internal-kms", 600684], ["flake8-builtins", 600375], ["pylint-gitlab", 599862], ["databricks-langchain", 599728], ["nbqa", 599267], ["apache-airflow-providers-dbt-cloud", 599195], ["prelude-python-sdk", 598936], ["mwparserfromhell", 598867], ["tensorboard-plugin-profile", 597890], ["ovh", 597652], ["bashkit", 597425], ["pytest-deadfixtures", 597336], ["json-schema-for-humans", 596439], ["pytest-clarity", 594845], ["python-json-config", 593812], ["bindep", 593649], ["pycdlib", 592928], ["flyteidl", 592847], ["dbt-trino", 592597], ["unicodedata2", 592446], ["pyrdfa3", 592097], ["currencyconverter", 591957], ["jc", 591062], ["suds", 590585], ["pycrdt-websocket", 590031], ["ipaddr", 589866], ["alibabacloud-adb20211201", 589576], ["pydantic-argparse", 588460], ["jax-cuda12-pjrt", 587686], ["portend", 587656], ["haystack-ai", 587319], ["dafnyruntimepython", 587304], ["chonkie-core", 587261], ["django-admin-autocomplete-filter", 587082], ["types-greenlet", 586855], ["types-boto3-secretsmanager", 586447], ["pywatchman", 586216], ["polygon-api-client", 585429], ["setuptools-scm-git-archive", 585358], ["jax-cuda12-plugin", 585340], ["async-interrupt", 584718], ["gitdb2", 584339], ["google-cloud-functions", 584281], ["python3-logstash", 583974], ["robotframework-jsonlibrary", 583336], ["smithy-core", 582873], ["aws-sdk-signers", 582749], ["envoy-data-plane", 582596], ["tatsu", 582414], ["mcap-ros2-support", 582122], ["nkeys", 581184], ["cursor-sdk", 581112], ["ib-insync", 581079], ["smithy-http", 579870], ["pymacaroons", 579600], ["taskiq-aio-pika", 579496], ["apache-airflow-providers-oracle", 579404], ["pyapns-client", 579138], ["ibmcloudant", 579079], ["chainlit", 578940], ["daqp", 578845], ["smithy-json", 578416], ["robotframework-pabot", 578331], ["azure-ai-textanalytics", 578195], ["elasticsearch8", 578173], ["sqlite-anyio", 577452], ["smithy-aws-core", 577376], ["google-cloud-pipeline-components", 577192], ["treepoem", 577169], ["validate-pyproject", 576990], ["build123d", 576732], ["aqtinstall", 576604], ["sqlean-py", 576125], ["vercel-sandbox", 576006], ["django-watchfiles", 575947], ["prefect-client", 575892], ["wandb-workspaces", 575725], ["roundrobin", 575562], ["curated-tokenizers", 575240], ["b2sdk", 574939], ["koalas", 574734], ["mypy-boto3-emr", 574386], ["pottery", 574019], ["microsoft-agents-hosting-fastapi", 573748], ["coola", 572915], ["mecab", 572575], ["langgraph-supervisor", 572371], ["quantstats", 572218], ["langchain-cohere", 572034], ["adrf", 571972], ["aioesphomeapi", 571503], ["openinference-instrumentation-google-adk", 571125], ["smithy-aws-event-stream", 570907], ["aiohttp-sse", 570866], ["sphinxcontrib-bibtex", 570564], ["eclipse-zenoh", 570525], ["ag-ui-a2ui-toolkit", 570492], ["javaobj-py3", 570044], ["mypy-boto3-emr-serverless", 570005], ["python-fasthtml", 569825], ["win-unicode-console", 569778], ["snakemake-storage-plugin-s3", 569122], ["numpy-stl", 568976], ["toml-sort", 568812], ["langchain-fireworks", 568472], ["fluent-runtime", 567996], ["fuzzysearch", 567565], ["mysql-replication", 567040], ["curies", 566862], ["django-modelcluster", 566802], ["django-user-agents", 566447], ["mypy-boto3-acm", 566321], ["planarity", 565811], ["powertrain-build", 565159], ["types-pysocks", 564870], ["pyserial-asyncio", 564368], ["tqdm-multiprocess", 563934], ["murmurhash2", 562882], ["future-fstrings", 562568], ["apeye", 562237], ["opentok", 562186], ["bayesian-optimization", 562053], ["sqlalchemy-cockroachdb", 561686], ["lazify", 561657], ["django-test-migrations", 561208], ["dataframely", 560948], ["dash-cytoscape", 560875], ["nutree", 560558], ["uhi", 560400], ["gpxpy", 560309], ["polars-ols", 560170], ["iterators", 560134], ["python-logstash", 560082], ["doc8", 560048], ["tf-keras-nightly", 559328], ["pylint-actions", 559228], ["garminconnect", 559177], ["prettyprinter", 558780], ["osmium", 558634], ["oslo-log", 558235], ["js2py", 558003], ["vk-api", 557907], ["webdav4", 557492], ["spacy-curated-transformers", 557435], ["vercel-queue", 557303], ["types-aiobotocore-ses", 557092], ["azure-eventhub-checkpointstoreblob-aio", 556963], ["hyperscan", 556888], ["multiurl", 556852], ["sphinxcontrib-spelling", 556708], ["pvporcupine", 556665], ["streaming-form-data", 556623], ["seeuletter", 556466], ["openseespy", 556345], ["types-boto3-sts", 556283], ["mcp-server-time", 556170], ["pybtex-docutils", 556096], ["phonemizer-fork", 556055], ["cel-expr-python", 555986], ["nc-py-api", 555827], ["flake8-annotations", 555419], ["xmlunittest", 554950], ["exit-codes", 554611], ["bincopy", 554593], ["dj-stripe", 554536], ["aws-cdk-aws-lambda-python-alpha", 554309], ["flake8-junit-report-basic", 553525], ["honcho-ai", 553510], ["python-igraph", 553401], ["google-maps-places", 553360], ["pymupdfpro", 552853], ["sql-formatter", 552388], ["ansiwrap", 552151], ["oslo-context", 552066], ["literalai", 551731], ["histoprint", 551608], ["cosmic-ray", 551538], ["awscurl", 551440], ["dapr", 551328], ["whisper-normalizer", 551026], ["cherrypy", 550976], ["xvfbwrapper", 550959], ["rotary-embedding-torch", 550465], ["pyatlan", 550400], ["exponent-server-sdk", 550019], ["logfury", 549345], ["mypy-boto3-comprehend", 549011], ["django-encrypted-model-fields", 548696], ["mlx-lm", 548449], ["openseespylinux", 548430], ["trio-typing", 548373], ["langchain-azure-ai", 548353], ["swapper", 548244], ["sqids", 548003], ["ib-async", 547929], ["blackduck", 547920], ["oslex", 547857], ["notion", 547856], ["great-expectations-experimental", 547712], ["curated-transformers", 547478], ["az-cli", 547444], ["waiting", 546933], ["py-machineid", 546830], ["kedro-telemetry", 546817], ["prefixed", 546599], ["mkdocs-meta-manager", 546587], ["dbt-fabric", 546326], ["django-tinymce", 546057], ["flagembedding", 545717], ["bugsnag", 545476], ["bleak-retry-connector", 545028], ["simpleflow", 544995], ["apache-airflow-providers-trino", 544962], ["python-mimeparse", 544731], ["ada-url", 544597], ["socketswap", 544072], ["mplcursors", 543680], ["google-cloud-eventarc-publishing", 543565], ["names", 543333], ["quickjs-rs", 543240], ["awesomeversion", 543166], ["transforms3d", 543030], ["lcov-cobertura", 542813], ["progressbar", 541946], ["unitycatalog-langchain", 541110], ["django-annoying", 541078], ["willow", 539902], ["music21", 539450], ["sphinx-lint", 539227], ["mkdocs-link-marker", 539177], ["types-smorest", 539032], ["poetry-plugin-pypi-mirror", 538660], ["memfabric-hybrid", 538466], ["djangorestframework-types", 538029], ["mypy-boto3-sagemaker-runtime", 537639], ["pybars3", 537535], ["jsonschema-spec", 537190], ["asyncio-throttle", 536518], ["great-tables", 536240], ["mypy-boto3-sso-admin", 536115], ["pytest-find-dependencies", 536084], ["nvidia-cuda-cccl-cu12", 536025], ["types-fpdf2", 535971], ["mailchimp-marketing", 535540], ["pystow", 535122], ["mkdocs-auto-tag-plugin", 534685], ["wmi", 534252], ["doit", 534078], ["mir-eval", 533904], ["python-interface", 533807], ["apache-airflow-client", 533757], ["djangosaml2", 533624], ["pandarallel", 533251], ["python-pcapng", 533119], ["chalkpy-rs", 533109], ["linkml-runtime", 532742], ["langchain-nvidia-ai-endpoints", 532499], ["clang-tidy", 532058], ["jupyter-packaging", 531999], ["azure-ai-translation-document", 531606], ["tensorrt-cu12", 531494], ["clevercsv", 531116], ["pytest-variables", 530994], ["llama-cpp-python", 530988], ["fastapi-azure-auth", 530938], ["scikit-optimize", 530663], ["monkeytype", 529716], ["caldav", 529699], ["types-aiobotocore-ecs", 529332], ["pymeshlab", 529082], ["mypy-boto3-elasticache", 529080], ["arckit", 528501], ["dbt-athena-community", 528337], ["pypiserver", 528018], ["lunr", 527907], ["bfi", 527812], ["json-logic-qubit", 527701], ["nose2", 527413], ["appengine-python-standard", 527279], ["aeventkit", 526674], ["decord2", 526665], ["sbvirtualdisplay", 526413], ["postgres-mcp", 526268], ["pyicu", 526133], ["opentelemetry-exporter-prometheus-remote-write", 526035], ["azure-storage", 525854], ["pyhwp", 525730], ["launchdarkly-api", 525552], ["proxy-py", 525301], ["opencc", 524600], ["types-qrcode", 524576], ["lefthook", 524568], ["ratelimiter", 523863], ["sphinxcontrib-websupport", 523643], ["pythran", 523628], ["indic-numtowords", 523627], ["piccolo", 523450], ["singer-python", 523432], ["enlighten", 523024], ["earthengine-api", 522340], ["postgrid-python", 522208], ["opensearch-dsl", 521888], ["einshape", 521558], ["mapclassify", 521511], ["libhoney", 521128], ["apispec-webframeworks", 520836], ["mdit-plain", 520582], ["selenium-wire", 520047], ["sgfmill", 519940], ["cloudconvert", 519879], ["fluent-logger", 519839], ["base32-crockford", 519320], ["optuna-integration", 519190], ["starrocks", 519139], ["mdformat-tables", 518767], ["pulumi-azuread", 518453], ["demucs", 518388], ["skyfield", 518366], ["xprof", 518129], ["cibuildwheel", 517861], ["correctionlib", 517608], ["rev-ai", 517443], ["mypy-boto3-opensearch", 517227], ["requests-ratelimiter", 517167], ["bloom-filter2", 517058], ["delighted", 516593], ["hdrhistogram", 516337], ["unitycatalog-openai", 516140], ["pymatgen-core", 516082], ["typeid-python", 515935], ["zmq", 515516], ["jschon", 515126], ["plux", 514494], ["autodocsumm", 514344], ["cmudict", 514269], ["nixl-cu13", 514255], ["sqloxide", 514220], ["types-aiobotocore-stepfunctions", 514115], ["chalice", 514109], ["pytest-examples", 513656], ["teamcity-messages", 512467], ["asyncio-mqtt", 512330], ["mypy-boto3-resourcegroupstaggingapi", 512267], ["json-ref-dict", 512152], ["numdifftools", 511306], ["ffmpeg", 511194], ["backports-ssl-match-hostname", 510877], ["logtail-python", 510826], ["fastokens", 510733], ["databricks-openai", 510679], ["prefixcommons", 510679], ["whisper", 510548], ["rdflib-jsonld", 510443], ["pyjwt-key-fetcher", 510401], ["cdk8s", 510398], ["azure-ai-agentserver-core", 510360], ["json-flatten", 510302], ["treelite", 510294], ["prefixmaps", 510160], ["mypy-boto3-iot", 510070], ["django-fsm", 509998], ["telepath", 509631], ["commented-configparser", 509575], ["pcpp", 509550], ["intersystems-irispython", 509326], ["python-hostlist", 509294], ["pgqueuer", 508700], ["hbreader", 508411], ["faicons", 508378], ["beniget", 508363], ["swagger-spec-validator", 508195], ["llm", 508092], ["pony", 508055], ["jsonasobj2", 507925], ["flytekit", 507700], ["json-flattener", 507657], ["zope-component", 507523], ["check-manifest", 507141], ["socks", 506854], ["mycdp", 506667], ["html-sanitizer", 506333], ["cocotb", 506277], ["opencage", 506254], ["markdown-graphviz-inline", 506249], ["pyttsx3", 506232], ["apache-airflow-providers-redis", 505787], ["misaki", 505754], ["pytest-mypy", 505721], ["pingouin", 505598], ["acsylla", 505449], ["aiocron", 505155], ["pocketsphinx", 505054], ["microsoft-kiota-bundle", 504844], ["xatlas", 504729], ["jinjasql", 504666], ["sphinx-markdown-builder", 504069], ["pydrive2", 504007], ["colorthief", 503945], ["fireblocks", 503885], ["syncer", 503871], ["aiooui", 503565], ["mypy-boto3-backup", 503394], ["bluetooth-adapters", 503206], ["apache-airflow-providers-tableau", 502950], ["alibabacloud-dingtalk", 502607], ["kubernetes-stubs", 502570], ["airbyte", 502542], ["propelauth-py", 502394], ["claude-code-sdk", 502373], ["pygame-ce", 502236], ["keyrings-cryptfile", 502069], ["mt-940", 501879], ["tinysegmenter", 501708], ["ptable", 500852], ["django-jsonform", 500524], ["types-xlrd", 499973], ["dagster-spark", 499743], ["openqasm3", 499734], ["thop", 499298], ["lunarcalendar", 499255], ["sphn", 498794], ["brickflows", 498633], ["g2p-en", 498472], ["ipwhois", 498181], ["untokenize", 497304], ["tuspyserver", 497240], ["django-permissionedforms", 497167], ["sampleproject", 497074], ["drf-standardized-errors", 496765], ["cysignals", 496643], ["django-cleanup", 496636], ["ai-edge-litert", 496414], ["pymsalruntime", 496381], ["gcloud", 496358], ["webrtcvad", 496011], ["targ", 495930], ["transaction", 495705], ["runloop-api-client", 495418], ["docx2pdf", 494804], ["dagster-pyspark", 494660], ["sgl-deep-ep", 494583], ["zss", 494228], ["nemoguardrails", 494132], ["atlassian-jwt-auth", 494053], ["fastdtw", 493943], ["fixtures", 493808], ["django-q2", 492967], ["mypy-boto3-s3control", 492913], ["inotify-simple", 492319], ["pytest-doctestplus", 491975], ["2captcha-python", 491706], ["django-sslserver", 491645], ["amplitude-experiment", 491293], ["torch-einops-utils", 491122], ["py3langid", 489969], ["metaflow", 489830], ["scikit-fem", 489595], ["pyapacheatlas", 489578], ["ag-ui-langgraph", 489412], ["adbc-driver-sqlite", 489329], ["nemo-toolkit", 489290], ["usb-devices", 488912], ["opentelemetry-test-utils", 488670], ["sklearn-crfsuite", 488607], ["pyjks", 488602], ["omnibase-spi", 488530], ["twofish", 488413], ["django-mathfilters", 488393], ["mypy-boto3-efs", 487803], ["microsoft-opentelemetry", 487797], ["kneed", 487509], ["zope-hookable", 487361], ["intel-cmplr-lib-ur", 486762], ["mypy-boto3-cloudfront", 486707], ["condense-json", 486277], ["pybullet", 486250], ["python-swiftclient", 485946], ["osmnx", 485886], ["pypac", 485871], ["django-auth-ldap", 485285], ["pysnooper", 485099], ["bleach-allowlist", 484676], ["pyperf", 484605], ["nvidia-ml-py3", 484393], ["sqlmesh", 484336], ["jupyter-dash", 484079], ["zulip", 484037], ["testrail-api", 483854], ["pycrdt-store", 483771], ["mcp-server-fetch", 483297], ["rclone-python", 483231], ["django-recaptcha", 483048], ["rules", 481259], ["featuremanagement", 481247], ["types-aiobotocore-elbv2", 481183], ["noiseprotocol", 480836], ["mypy-boto3-identitystore", 480730], ["tortoise-orm", 480486], ["python-sat", 480220], ["uart-devices", 480218], ["google-cloud-ndb", 480123], ["keyboard", 479665], ["microsoft-teams-cards", 479620], ["langchainhub", 479316], ["salesforce-fuelsdk-sans", 479024], ["quadprog", 478984], ["json-delta", 478920], ["miniopy-async", 478414], ["webexteamssdk", 477709], ["fnv-hash-fast", 477685], ["microsoft-teams-common", 477476], ["pydotplus", 477182], ["openai-guardrails", 477099], ["types-aiobotocore-events", 477033], ["python-backoff", 476918], ["azure-storage-nspkg", 476870], ["pandas-datareader", 475973], ["cursor", 475740], ["cxxfilt", 475714], ["sgl-deep-gemm", 475663], ["robotframework-assertion-engine", 475482], ["local-crontab", 475195], ["lpc-checksum", 475133], ["formic2", 474903], ["azure-eventhub-checkpointstoreblob", 473811], ["rule-engine", 473377], ["cvc5", 473153], ["adbc-driver-flightsql", 473053], ["autologging", 473026], ["linkml", 472465], ["shodan", 472130], ["authres", 471994], ["k8", 471426], ["discord-webhook", 471114], ["pytest-cover", 470750], ["mypy-boto3-codepipeline", 470556], ["osc-lib", 470549], ["coralogix-logger", 470510], ["microsoft-teams-api", 470437], ["google-antigravity", 470342], ["pytest-describe", 470083], ["vector", 470048], ["dspy-ai", 469970], ["pypika-tortoise", 469820], ["certbot-dns-cloudflare", 469321], ["flask-script", 468922], ["gmpy2", 468354], ["basic-pitch", 468159], ["urllib3-secure-extra", 468088], ["certbot", 467732], ["ensure", 467666], ["pyjsg", 467588], ["home-assistant-bluetooth", 467483], ["plyvel", 466684], ["shexjsg", 466637], ["pyshex", 466312], ["wemake-python-styleguide", 466194], ["types-aiobotocore-route53", 466190], ["corner", 466175], ["gcloud-aio-pubsub", 466111], ["pyshexc", 466110], ["nixl", 465855], ["gcs-oauth2-boto-plugin", 465631], ["structlog-gcp", 465317], ["django-rest-passwordreset", 464833], ["arviz-stats", 464365], ["ulid-transform", 464364], ["eml-parser", 464342], ["aspose-words", 463984], ["laces", 463674], ["dbl-discoverx", 463175], ["cpplint", 463156], ["ftputil", 463130], ["prefect-kubernetes", 463102], ["kokoro-onnx", 463074], ["clipboard", 462984], ["botorch", 462670], ["drf-writable-nested", 462256], ["anyconfig", 462071], ["zope-schema", 461838], ["django-upgrade", 461769], ["allure-behave", 461460], ["newspaper3k", 461371], ["drain3", 461201], ["apache-airflow-providers-apache-spark", 461107], ["flask-basicauth", 460899], ["pip-hello-world", 460774], ["keplergl", 460558], ["djangoql", 460175], ["wheel-filename", 460056], ["flask-openapi3", 459880], ["rq-scheduler", 459689], ["jieba3k", 459677], ["liger-kernel", 459589], ["volcengine-python-sdk", 459516], ["slacker", 459081], ["hass-nabucasa", 459046], ["pyftdi", 458725], ["gladiaio-sdk", 458601], ["pywhispercpp", 458308], ["azure-mgmt-databricks", 458186], ["mypy-boto3-apigatewayv2", 458172], ["botbuilder-integration-aiohttp", 458031], ["macaroonbakery", 457891], ["jsonasobj", 457404], ["langgraph-checkpoint-aws", 457368], ["dagster-databricks", 457284], ["tokie", 457244], ["cvdupdate", 456899], ["python-graphql-client", 456624], ["compoundfiles", 456472], ["unoserver", 456071], ["clearml-agent", 455935], ["cantera", 455874], ["rdflib-shim", 455852], ["promql-parser", 455572], ["tencentcloud-sdk-python", 455476], ["contextily", 455463], ["sspilib", 455310], ["cw-rpa", 455247], ["types-flask-cors", 455057], ["dagster-polars", 454796], ["pytest-ansible", 454719], ["faktory", 454421], ["flashrank", 454287], ["types-aiobotocore-batch", 454227], ["fixit", 454225], ["sparqlslurper", 454220], ["ringcentral", 454060], ["llama-index-llms-azure-openai", 453368], ["forex-python", 453251], ["django-fsm-2", 453193], ["pluginlib", 453159], ["verboselogs", 452938], ["ops", 452873], ["types-gevent", 452816], ["pylint-celery", 452781], ["pybind11-global", 452110], ["qiskit-aer", 452099], ["serpapi", 451714], ["feedfinder2", 451439], ["types-dataclasses", 451318], ["couchbase", 451251], ["vtracer", 451176], ["pyhpke", 451099], ["lexid", 451037], ["xdg", 450969], ["nplusone", 450579], ["openviking", 450362], ["types-auth0-python", 450313], ["pipelinewise-singer-python", 450256], ["bpy", 450128], ["pytest-coverage", 450030], ["pyminizip", 449576], ["pyscipopt", 448998], ["omnibase-compat", 448974], ["delta", 448964], ["jaxopt", 448897], ["mkdocs-include-markdown-plugin", 448858], ["pyrage", 448366], ["mail-parser-reply", 448256], ["kubernetes-stubs-elephant-fork", 448202], ["pandas-ta", 447874], ["qwix", 447677], ["sphinx-prompt", 447371], ["django-ordered-model", 447255], ["taplo", 447127], ["bumpver", 447101], ["httpagentparser", 447042], ["azure-mgmt-costmanagement", 446785], ["types-zxcvbn", 446621], ["common-expression-language", 446101], ["lakefs-sdk", 446063], ["flake8-debugger", 445852], ["sphinx-notfound-page", 445708], ["dsnparse", 445680], ["agentevals", 445617], ["easy-thumbnails", 445545], ["uncurl", 445513], ["types-boto3-bedrock-runtime", 445395], ["polars-lts-cpu", 444841], ["pydrive", 444609], ["pybuildkite", 444555], ["jsf", 444467], ["coffea", 444431], ["mypy-boto3-cognito-identity", 444375], ["hdf5plugin", 444335], ["awslabs-aws-documentation-mcp-server", 444318], ["ladybug", 444278], ["sqlalchemy-mixins", 444185], ["django-select2", 443865], ["sqlalchemy-pytds", 443545], ["bluetooth-auto-recovery", 443525], ["pennylane-lightning", 443237], ["torch-fidelity", 443157], ["filehash", 443072], ["detect-agent", 442950], ["patchy", 442598], ["jamo", 442570], ["celery-progress", 442540], ["descartes", 442029], ["prefab-ui", 441810], ["openai-chatkit", 441778], ["aws-cdk-aws-glue-alpha", 441427], ["kaldiio", 441425], ["snitun", 441310], ["hyperscript", 441243], ["atomicwrites-homeassistant", 440645], ["pytest-md", 440540], ["requests-unixsocket2", 440256], ["spider-client", 440152], ["pulumi-tailscale", 439736], ["ir-datasets", 439696], ["langgraph-checkpoint-mongodb", 438758], ["certvalidator", 438648], ["django-bulk-update", 438557], ["mypy-boto3-application-autoscaling", 438239], ["python-louvain", 438203], ["cognitive-complexity", 437829], ["gpiod", 437826], ["nested-lookup", 437585], ["mypy-boto3-transfer", 437576], ["smolagents", 437081], ["effdet", 436905], ["c2pa-python", 436753], ["jupyter-server-proxy", 436442], ["pytest-pylint", 436398], ["nanopb", 436209], ["hvplot", 435991], ["types-pycurl", 435483], ["flake8-black", 435267], ["types-aiobotocore-iot", 435239], ["pymatgen-io-validation", 435128], ["langchain-quickjs", 434962], ["flask-pydantic", 434833], ["sorl-thumbnail", 434755], ["google-events", 434647], ["veracode-api-signing", 434613], ["types-aiobotocore-iot-data", 434339], ["runai-model-streamer", 434330], ["cache-dit", 434284], ["edn-format", 434107], ["vector-quantize-pytorch", 434054], ["lazy", 433891], ["opensandbox", 433824], ["pyric", 433644], ["btsocket", 433374], ["aic-sdk", 433213], ["conjure-python-client", 433192], ["aws-sdk-bedrock-runtime", 432875], ["pulumi-github", 432587], ["lhotse", 432410], ["mypy-boto3-bedrock-agentcore", 432019], ["oauth2", 431649], ["libarchive-c", 431487], ["brainstem", 431218], ["flake8-use-fstring", 431218], ["mwaa-dr", 431198], ["hyperliquid-python-sdk", 431122], ["libpff-python", 430218], ["tesserocr", 430192], ["docx", 430059], ["pytest-parallel", 429957], ["routes", 429791], ["nncf", 429756], ["python-youtube", 429203], ["databricks-pypi-extras", 429173], ["peakrdl-ipxact", 428872], ["django-split-settings", 428756], ["loudness", 428540], ["langchain-pinecone", 428153], ["mmdb-writer", 428150], ["mypy-boto3-cloudtrail", 427386], ["types-aiobotocore-elasticache", 427130], ["nixl-cu12", 426722], ["django-add-default-value", 426373], ["uipath-runtime", 426373], ["requestsexceptions", 426006], ["pyvista-validation", 425891], ["types-google-cloud-ndb", 425806], ["asyncpg-trek", 425675], ["fakesnow", 425427], ["imgkit", 425197], ["google-cloud-profiler", 425040], ["xrootd", 424988], ["autogen-core", 424980], ["toon-format", 424804], ["pytest-lazy-fixture", 424712], ["salib", 424532], ["netsuitesdk", 424256], ["rio-tiler", 424193], ["cupy-cuda13x", 424071], ["pytest-homeassistant-custom-component", 423954], ["django-sendgrid-v5", 423912], ["case-conversion", 423843], ["pypi-timemachine", 423251], ["posix-ipc", 423128], ["rapids-logger", 422871], ["srptools", 422300], ["torchinfo", 421886], ["python-string-utils", 421621], ["tbats", 421589], ["pystac-client", 421488], ["aiopg", 421440], ["flake8-commas", 421351], ["typer-config", 421290], ["credstash", 421261], ["winrt-runtime", 420978], ["mypy-boto3-ce", 420626], ["apted", 420619], ["odg-client", 420603], ["mplfinance", 420580], ["gmsh", 420578], ["celery-singleton", 420563], ["mjml-python", 420546], ["cdsapi", 420458], ["faster-coco-eval", 420408], ["lapx", 419978], ["allure-combine", 419628], ["unidic", 419524], ["aiobreaker", 419365], ["aiozoneinfo", 419364], ["mkdocs-github-admonitions-plugin", 419348], ["jenkinsapi", 419164], ["python-bitcoinlib", 418727], ["pydantic-to-typescript", 418520], ["smartystreets-python-sdk", 418327], ["jsonpath-rw-ext", 418060], ["helion", 417914], ["ibm-db-sa", 417802], ["sqlalchemy-hana", 417718], ["piccolo-api", 417304], ["securetar", 417208], ["unlzw3", 416905], ["simpervisor", 416340], ["pyld", 416312], ["matrice", 415948], ["sphinx-gallery", 415807], ["s2sphere", 415597], ["optimizely-sdk", 415507], ["pymannkendall", 415136], ["reverse-geocoder", 415046], ["nbval", 414763], ["mypy-boto3-redshift", 414723], ["okta-jwt-verifier", 414653], ["smmap2", 414411], ["pygal", 413981], ["pymobiledevice3", 413815], ["django-tailwind", 413780], ["acachecontrol", 413607], ["timing-asgi", 413210], ["google-cloud-billing", 412894], ["coiled", 412843], ["bert-score", 412801], ["amqpstorm", 412631], ["matrice-inference", 412531], ["ansible-builder", 412245], ["coloraide", 412083], ["proxmoxer", 411957], ["types-aiobotocore-glue", 411846], ["piccolo-admin", 411530], ["yandex-query-client", 411290], ["mailgun", 411145], ["django-fernet-encrypted-fields", 410826], ["matrice-analytics", 410649], ["tika", 410577], ["djangorestframework-xml", 410576], ["winrt-windows-foundation", 410370], ["uipath-platform", 410292], ["ddddocr", 410286], ["matrice-streaming", 410158], ["sagemaker-feature-store-pyspark-3-3", 410048], ["datadog-logger", 409905], ["paramiko-expect", 409455], ["pytest-selenium", 409438], ["matrice-common", 409382], ["grpcio-testing", 409318], ["pyexcelerate", 409307], ["llama-index-vector-stores-postgres", 408683], ["maggma", 408585], ["azure-ai-agentserver-invocations", 408573], ["certbot-dns-multi", 408454], ["check-wheel-contents", 408053], ["human-eval", 407531], ["dbus-next", 407513], ["tencentcloud-sdk-python-wsa", 407198], ["dtlpymetrics", 407187], ["case-converter", 407115], ["inotify", 407001], ["setuptools-golang", 406625], ["psutil-home-assistant", 406180], ["quinn", 406101], ["types-babel", 406080], ["rocketchat-api", 405777], ["japanize-matplotlib", 405566], ["esp-idf-size", 405542], ["datarobot", 405442], ["color-operations", 405308], ["azure-mgmt-databoxedge", 405278], ["umf", 404561], ["pyiso8583", 404396], ["triton-windows", 404392], ["pynitefea", 404255], ["symspellpy", 403788], ["ofxparse", 403743], ["licensecheck", 403692], ["pytest-harvest", 403655], ["shillelagh", 403604], ["mock-ssh-server", 403552], ["types-aiobotocore-cloudtrail", 403527], ["opentelemetry-instrumentation-pymssql", 402930], ["mypy-boto3-dms", 402653], ["mypy-boto3-codedeploy", 402237], ["reverse-geocode", 402223], ["python-terraform", 402125], ["mpld3", 402094], ["sphinx-toolbox", 401871], ["bigtree", 401803], ["pyhdfe", 401587], ["zope-configuration", 401552], ["pulumi-snowflake", 401379], ["starlark-pyo3", 401207], ["onnxsim", 401e3], ["google-cloud-bigquery-logging", 400979], ["simpy", 400932], ["autoray", 400882], ["ovld", 400746], ["ecmwf-datastores-client", 400694], ["robotframework-retryfailed", 400664], ["scim2-models", 400604], ["setuptools-git", 400573], ["spacy-pkuseg", 400487], ["django-postgres-extra", 400162], ["extra-streamlit-components", 399887], ["dvc-gs", 399865], ["checksumdir", 399703], ["lemminflect", 399657], ["python-certifi-win32", 399208], ["django-jazzmin", 399104], ["sphinx-jinja2-compat", 399034], ["webrtc-models", 398231], ["pylibmc", 397970], ["pyspark-test", 397430], ["bz2file", 397417], ["backports-abc", 397348], ["baseten-performance-client", 397248], ["rospkg", 396972], ["munkres", 396794], ["numpydantic", 396575], ["django-hosts", 396235], ["types-aiobotocore-wafv2", 396170], ["seekpath", 396029], ["lime", 395908], ["google-reauth", 395841], ["autogen-agentchat", 395840], ["mozfile", 395728], ["types-aiobotocore-route53domains", 395728], ["winrt-windows-foundation-collections", 395356], ["python-lsp-ruff", 395068], ["symusic", 395007], ["types-aiobotocore-verifiedpermissions", 394907], ["modelsearch", 394812], ["scalene", 394589], ["livereload", 394522], ["chalkpy", 394387], ["pysodium", 394383], ["google-maps-routeoptimization", 394297], ["cement", 394260], ["django-configurations", 394227], ["jupyter-nbextensions-configurator", 394199], ["cognitojwt", 394153], ["django-permissions-policy", 394024], ["types-aiobotocore-iot-jobs-data", 393812], ["textual-dev", 393729], ["zope-i18nmessageid", 393682], ["openfeature-provider-flagsmith", 393613], ["playa-pdf", 393513], ["github-action-utils", 393369], ["a2ui-agent-sdk", 393342], ["apache-airflow-providers-airbyte", 393293], ["dict2css", 393197], ["opentelemetry-instrumentation-asyncclick", 393167], ["git-remote-s3", 393106], ["jinja2-strcase", 393070], ["typedspark", 392570], ["asyncmy2", 392562], ["markdown-pdf", 392457], ["jurigged", 392272], ["convertapi", 391547], ["attrdict", 391411], ["chia-rs", 390525], ["codefind", 390412], ["dagster-snowflake", 390325], ["llama-index-embeddings-google-genai", 389687], ["aerosandbox", 389465], ["fusepy", 389277], ["segmentation-models-pytorch", 389181], ["truelayer-signing", 388832], ["siphash24", 388803], ["numba-cuda", 388637], ["backports-shutil-get-terminal-size", 388495], ["types-pywin32", 388405], ["feedgen", 388363], ["localstack", 388047], ["aliyun-log-python-sdk", 387904], ["loop-rate-limiters", 387665], ["functools32", 387278], ["mongo-query-match", 386324], ["mujoco-warp", 386209], ["stream-chat", 386200], ["textsearch", 385996], ["dbus-python", 385840], ["npmai-agents", 385753], ["google-agents-cli", 385431], ["deap", 385212], ["google-cloud-sqlcommenter", 385130], ["pycosat", 384776], ["pyfaidx", 384661], ["teradataml", 384650], ["pydoe", 384567], ["nylas", 384536], ["openxlab", 384249], ["colorhash", 384166], ["lzfse", 383949], ["infi-systray", 383893], ["prettierfier", 383737], ["gin-config", 383646], ["groundx", 383630], ["delocate", 383376], ["tf-models-nightly", 383164], ["streamlit-option-menu", 383149], ["asyncio-gevent", 383117], ["zhconv", 382977], ["files-com", 382749], ["toml-cli", 382749], ["jarowinkler", 382666], ["gdal", 382515], ["better-exceptions", 382310], ["qualname", 382108], ["google-cloud-agentidentitycredentials", 382017], ["entsoe-py", 381997], ["segment-anything", 381837], ["multimark", 381817], ["mypy-boto3-transcribe", 381266], ["u-msgpack-python", 381218], ["aiohttp-asyncmdnsresolver", 381093], ["pysubtypes", 381049], ["nominal-api", 381016], ["pymiscutils", 380969], ["pyvrl", 380878], ["pyiotools", 380817], ["pathmagic", 380684], ["ocsf-lib", 380387], ["maybe-else", 380170], ["econml", 380108], ["apache-superset", 380102], ["pylint-pytest", 379950], ["office365", 379671], ["pyspice", 379570], ["hive-metastore-client", 379525], ["qiskit-ibm-runtime", 379442], ["djhtml", 379389], ["aioimaplib", 379369], ["types-aiobotocore-identitystore", 379348], ["neuralfoil", 379303], ["xonsh", 379214], ["pandapower", 379180], ["python-amazon-sp-api", 378597], ["msgfy", 378579], ["flake8-rst-docstrings", 378336], ["sphinx-sitemap", 378288], ["mock-open", 378193], ["frappe-bench", 378063], ["tokamax", 378057], ["types-typed-ast", 377908], ["pysigma", 377851], ["jobflow", 377818], ["pyct", 377634], ["mariadb", 377507], ["python-toon", 377264], ["anastruct", 377219], ["mozlog", 377111], ["prefect-shell", 376936], ["tinytuya", 376537], ["nbmake", 376417], ["icalendar-searcher", 376330], ["nokap", 376066], ["abx-plugins", 376044], ["sqlalchemy-trino", 375818], ["django-solo", 375785], ["youdotcom", 375314], ["browsergym-core", 375275], ["mypy-boto3-dataexchange", 375166], ["transformers-stream-generator", 374979], ["aiohasupervisor", 374311], ["nicknames", 374125], ["llm-sandbox", 373968], ["splitio-client", 373671], ["alembic-git-revisions", 373447], ["opentelemetry-exporter-jaeger-thrift", 373319], ["axiom-py", 373262], ["microsoft-teams-apps", 373144], ["pyjwkest", 372954], ["mypy-boto3-s3tables", 372952], ["dm-env", 372902], ["primer3-py", 372436], ["liteparse", 372370], ["mozterm", 372316], ["seqeval", 372253], ["alembic-autogenerate-enums", 372212], ["jsonseq", 372103], ["python-nmap", 371795], ["pyspark-hnsw", 371741], ["py-cord", 371587], ["async-asgi-testclient", 371364], ["types-ipaddress", 371232], ["validator-collection", 371139], ["pmtiles", 371053], ["mypy-boto3-appconfig", 371027], ["xmltojson", 370981], ["dmpython", 370725], ["rispy", 370677], ["mypy-boto3-rds-data", 370566], ["instanttensor", 370532], ["pytest-skip-slow", 370481], ["pin-pink", 370028], ["python-openstackclient", 369541], ["opentelemetry-instrumentation-exceptions", 369455], ["jupyter-highlight-selected-word", 369338], ["oslo-concurrency", 369268], ["klepto", 369199], ["quart-cors", 369113], ["rectpack", 369033], ["py-builder-signing-sdk", 368949], ["frida-tools", 368874], ["apache-airflow-providers-salesforce", 368833], ["auto-round", 368712], ["opentelemetry-contrib-instrumentations", 368605], ["git-python", 368299], ["pytest-cmake", 368177], ["py-consul", 367716], ["axe-playwright-python", 367626], ["mkdocs-static-i18n", 367325], ["cacheout", 367166], ["pytest-assume", 366966], ["contractions", 366848], ["arviz-base", 366699], ["agent-framework-foundry", 366319], ["openinference-instrumentation-pydantic-ai", 366256], ["django-better-admin-arrayfield", 365892], ["gilknocker", 365818], ["aioshutil", 365811], ["pysnmpcrypto", 365751], ["pyang", 365709], ["pytools", 365652], ["daemonize", 365611], ["jupyter-contrib-nbextensions", 365586], ["pymorphy3", 365355], ["mygeotab", 365315], ["django-bootstrap5", 365293], ["mypy-boto3-appconfigdata", 365233], ["optimum-onnx", 365070], ["types-ldap3", 365031], ["pysqlite3", 364928], ["pymorphy3-dicts-ru", 364853], ["django-ninja-extra", 364804], ["sanic-ext", 364789], ["arviz-plots", 364370], ["serpyco-rs", 364274], ["mkl", 364104], ["pytest-mpl", 363869], ["rstcheck", 363848], ["sphinx-last-updated-by-git", 363770], ["alexapy", 363768], ["keras-hub", 363494], ["jsonformatter", 363261], ["captum", 362774], ["pysolr", 362649], ["jupyter-kernel-gateway", 362575], ["openinference-instrumentation-haystack", 362311], ["kaldialign", 362305], ["jupyter-contrib-core", 362107], ["textual-autocomplete", 361969], ["toolbox-core", 361776], ["iso639-lang", 361655], ["comet-ml", 361457], ["single-source", 360937], ["lauterbach-trace32-rcl", 360907], ["saq", 360639], ["types-jwcrypto", 360630], ["contentful", 360475], ["sqlalchemy-rdsiam", 360414], ["aurora-data-api", 360053], ["bech32", 359995], ["py-clob-client", 359993], ["mne", 359966], ["foxglove-sdk", 359738], ["wasmer", 359700], ["snuggs", 359629], ["colormath", 359481], ["textile", 358849], ["pwlf", 358678], ["arctic-inference", 358521], ["django-imagekit", 358463], ["cppy", 358409], ["tgcrypto", 358330], ["triangle", 358324], ["segtok", 358296], ["pytest-logging", 358218], ["langchain-ibm", 358208], ["pilkit", 358043], ["notifiers", 357892], ["mypy-boto3-wafv2", 357139], ["qudida", 357071], ["bertopic", 356881], ["common", 356813], ["grafana-foundation-sdk", 356797], ["moyopy", 356563], ["qstash", 356443], ["flake8-return", 356383], ["cli-helpers", 356238], ["pgsanity", 355958], ["retry-decorator", 355835], ["sqlalchemy-aurora-data-api", 355637], ["flake8-async", 355516], ["cpuset-py3", 355237], ["types-olefile", 354652], ["encodec", 354377], ["types-pkg-resources", 353883], ["python-etcd", 353833], ["langextract", 353238], ["protobuf-to-pydantic", 352866], ["cdktf", 352838], ["tarsafe", 352687], ["pydeps", 352549], ["django-celery-email", 352335], ["keybert", 352296], ["openhands-workspace", 352273], ["sanitize-filename", 351924], ["pylru", 351812], ["gcloud-rest-auth", 351785], ["llama-index-embeddings-azure-openai", 351695], ["koheesio", 351682], ["whichcraft", 351679], ["arize-otel", 351539], ["langserve", 351519], ["xdis", 351335], ["crhelper", 351215], ["langwatch", 351146], ["flask-principal", 350928], ["facebook-sdk", 350776], ["sphinx-mdinclude", 350679], ["types-aiobotocore-sesv2", 350669], ["openai-clip", 350492], ["python-markdown-math", 350488], ["graypy", 350214], ["datetimerange", 350026], ["pytest-spark", 349908], ["pytest-pep8", 349867], ["hierarchical-conf", 349787], ["wasmer-compiler-cranelift", 349781], ["yara-x", 349772], ["redlines", 349760], ["cwcwidth", 349616], ["whisperx", 349584], ["curtsies", 349555], ["rbloom", 349515], ["tflite-runtime", 349392], ["entrypoint2", 349372], ["google-cloud-dns", 349045], ["schemachange", 349045], ["dawg2-python", 348946], ["vectorbt", 348795], ["rtfparse", 348752], ["odfdo", 348724], ["provide-dir", 348407], ["matplotlib-venn", 348273], ["watchgod", 348264], ["verlib2", 348238], ["django-pg-zero-downtime-migrations", 348122], ["dag-factory", 348067], ["pygount", 347970], ["praat-parselmouth", 347796], ["rstcheck-core", 347735], ["opencensus-ext-logging", 347703], ["imgaug", 347700], ["xdg-base-dirs", 347628], ["hyperbrowser", 347510], ["pyvo", 347275], ["truss", 347238], ["pygam", 346842], ["tinker-cookbook", 346799], ["rudder-sdk-python", 346722], ["libipld", 346518], ["pyink", 346482], ["fastdiff", 346417], ["yamlordereddictloader", 346404], ["aqtp", 346329], ["localstack-ext", 346296], ["everett", 345946], ["dbt-metricflow", 345718], ["attributes-doc", 345705], ["bpython", 345690], ["hass-web-proxy-lib", 345599], ["mssql-django", 345503], ["drf-orjson-renderer", 345338], ["linearmodels", 345300], ["requests-html", 344995], ["ipinfo", 344900], ["libpysal", 344881], ["cellpylib", 344877], ["pksuid", 344221], ["mypy-boto3-route53resolver", 344129], ["nautilus-trader", 344119], ["testresources", 344113], ["python-cinderclient", 344099], ["types-requests-oauthlib", 344066], ["ics", 344058], ["mozsystemmonitor", 343806], ["records", 343293], ["pycountry-convert", 343277], ["stackprinter", 343264], ["qiskit-qasm3-import", 342572], ["python-i18n", 342318], ["collate-sqllineage", 342099], ["bpylist2", 342017], ["isoweek", 341995], ["django-pgviews-redux", 341971], ["tsdownsample", 341586], ["requirements-detector", 341395], ["nominal", 341234], ["mplhep", 341163], ["types-pyjwt", 340988], ["pycln", 340662], ["lightkube-models", 340582], ["atproto", 340387], ["lakefs", 340341], ["astroquery", 340185], ["compress-pickle", 340131], ["torchlibrosa", 340097], ["hatch-protobuf", 339947], ["javalang", 339943], ["confluent-kafka-stubs", 339884], ["azure-mgmt-automation", 339862], ["lzstring", 339860], ["stochastic", 339668], ["abxpkg", 339648], ["megatron-core", 339602], ["lia-web", 339572], ["tfp-nightly", 339556], ["openfeature-flagd-core", 339534], ["openfeature-flagd-api", 339525], ["aiohomematic", 339091], ["lazr-uri", 338818], ["openhands-aci", 338786], ["unstructured-ingest", 338772], ["pwntools", 338740], ["djangorestframework-gis", 338505], ["pygresql", 338499], ["install-playwright", 337911], ["xmodem", 337620], ["phpserialize", 337513], ["django-elasticsearch-dsl", 337511], ["pot", 337387], ["flake8-string-format", 337382], ["futurist", 337175], ["fabric-analytics-sdk", 337106], ["filigran-sseclient", 336935], ["plantuml", 336878], ["dapr-ext-workflow", 336708], ["firebase-functions", 336635], ["tox-gh-actions", 336622], ["standard-telnetlib", 336557], ["executable-application", 336509], ["kuzu", 336311], ["univers", 336282], ["kiwipiepy", 336226], ["yellowbrick", 336123], ["pyturbojpeg", 336088], ["pyxtal", 336027], ["mplhep-data", 335944], ["imblearn", 335672], ["iniparse", 335272], ["django-cryptography-django5", 335094], ["snapshottest", 334953], ["mypy-boto3-ram", 334893], ["airbyte-protocol-models-dataclasses", 334872], ["fabric-analytics-notebook-plugin", 334787], ["pytest-unused-fixtures", 334663], ["mypy-boto3-iot-data", 334440], ["control", 334269], ["pyocse", 334052], ["sdbus", 333914], ["pydantic-ai-backend", 333859], ["stqdm", 333823], ["x-transformers", 333645], ["mypy-gitlab-code-quality", 333603], ["pyspark-pandas", 333506], ["vasprun-xml", 333382], ["chiapos", 333214], ["authheaders", 332864], ["flaml", 332857], ["chiavdf", 332745], ["vermin", 332597], ["aliyun-python-sdk-core-v3", 332121], ["mypy-boto3-docdb", 331741], ["fastai", 331739], ["trajectory-sdk", 331623], ["slicerator", 331609], ["pytest-csv", 331406], ["serpent", 331358], ["libretranslatepy", 331234], ["flash-attn", 331133], ["translate", 331126], ["blosc", 330933], ["aws-error-utils", 330875], ["flake8-tidy-imports", 330746], ["diskcache-stubs", 330512], ["truss-transfer", 330452], ["solace-pubsubplus", 330373], ["crosshair-tool", 330238], ["p-tqdm", 329860], ["collate-data-diff", 329569], ["prefect-sqlalchemy", 329505], ["simile", 329477], ["mypy-boto3-fis", 329238], ["genagent", 329159], ["supertokens-python", 329135], ["strsimpy", 328845], ["crispy-bootstrap4", 328818], ["pybars4", 328800], ["python-novaclient", 328675], ["rio-cogeo", 328654], ["biotraj", 328308], ["autogen-ext", 328278], ["clu", 328239], ["django-crum", 328020], ["leptonai", 327942], ["adbc-driver-snowflake", 327817], ["drf-jwt", 327794], ["livekit-plugins-ai-coustics", 327763], ["lineax", 327741], ["fast-array-utils", 327720], ["kernel", 327694], ["sepaxml", 327683], ["archspec", 327675], ["copilotkit", 327666], ["drf-extra-fields", 327629], ["pyu2f", 327605], ["types-hvac", 327591], ["mlforecast", 327491], ["sentence-stream", 327485], ["pook", 327480], ["littlefs-python", 327426], ["mink", 327393], ["label-studio-sdk", 327373], ["pydantic-function-models", 327221], ["exrex", 327219], ["collate-sqlfluff", 327041], ["fastapi-offline", 327020], ["ledoc-ui", 326936], ["spark-expectations", 326928], ["sybil", 326851], ["django-sass-processor", 326714], ["pytun-pmd3", 326496], ["mypy-boto3-es", 326405], ["flufl-bounce", 326400], ["microsoft-agents-a365-runtime", 326380], ["ropgadget", 326337], ["pytest-remotedata", 326301], ["pyap", 326180], ["wait-for2", 326134], ["nominal-api-protos", 326104], ["pymisp", 325994], ["mlx-whisper", 325961], ["microsoft-agents-a365-observability-core", 325817], ["json-diff", 325700], ["aioftp", 325394], ["abx-dl", 325381], ["empirical-calibration", 325304], ["pyghmi", 325234], ["zigpy", 325233], ["python-datauri", 325099], ["unix-ar", 325036], ["mypy-boto3-timestream-write", 324995], ["e3nn", 324839], ["podman", 324835], ["peakrdl-systemrdl", 324785], ["phidget22", 324770], ["django-autoslug", 324695], ["robosuite", 324604], ["deflate", 324514], ["collectfast", 324222], ["testscenarios", 324190], ["clickhouse-cityhash", 324100], ["pytailwindcss", 324088], ["ipsw-parser", 323984], ["secweb", 323984], ["fastapi-filter", 323976], ["importlib", 323961], ["tree-sitter-d2", 323762], ["cheetah3", 323759], ["mosek", 323755], ["giterator", 323295], ["pyimg4", 323095], ["chiabip158", 323086], ["chide", 323018], ["pytorch-ignite", 322984], ["pytest-trio", 322943], ["djoser", 322871], ["ptvsd", 322650], ["validations-engine", 322328], ["trackio", 322287], ["polars-hash", 322110], ["pytest-subprocess", 322072], ["sphinx-togglebutton", 322072], ["autodoc-pydantic", 322043], ["multiping", 321815], ["tox-ansible", 321747], ["opensearch-mcp-server-py", 321587], ["haystack-experimental", 321310], ["scrapingbee", 321297], ["asv", 321085], ["azure-ai-agentserver-responses", 321077], ["colored-traceback", 320901], ["grafanalib", 320838], ["types-aiobotocore-securityhub", 320612], ["openinference-instrumentation-llama-index", 320592], ["tree-sitter-hcl", 320488], ["celery-stubs", 320394], ["mypy-boto3-neptune", 320309], ["apache-airflow-providers-opsgenie", 320245], ["mypy-boto3-bedrock-agentcore-control", 320089], ["pylogbeat", 320036], ["pylightxl", 319988], ["py-clob-client-v2", 319841], ["aioping", 319767], ["mypy-boto3-kafka", 319627], ["concurrencytest", 319543], ["newton-usd-schemas", 319517], ["pysignalr", 319435], ["pyarmor", 319433], ["psycopg2-pool", 319348], ["pytest-md-report", 319259], ["xmlrunner", 319257], ["opt-einsum-fx", 319234], ["airflow-dbt", 319232], ["pygnuutils", 319225], ["cognite-sdk", 319172], ["datashader", 319027], ["parameter-decorators", 318918], ["autotyping", 318840], ["kenlm", 318815], ["pycrashreport", 318808], ["stumpy", 318773], ["pykdebugparser", 318741], ["qemu-qmp", 318730], ["policyuniverse", 318642], ["dataproc-spark-connect", 318564], ["landlock", 318272], ["types-flask-migrate", 318186], ["redfish", 318109], ["selenium-stealth", 318091], ["cfnresponse", 317967], ["meteostat", 317948], ["developer-disk-image", 317837], ["uipath-core", 317703], ["annotatedyaml", 317576], ["ghostscript", 317554], ["schemdraw", 317434], ["mypy-boto3-dynamodbstreams", 317215], ["vcver", 317141], ["ring-flash-attn", 316986], ["dagster-dlt", 316890], ["pyclean", 316824], ["ssh2-python", 316539], ["icalevents", 316530], ["streamsets", 316521], ["matrix-client", 316256], ["djangorestframework-filters", 316195], ["pgmpy", 316165], ["python-binance", 316143], ["html-tag-names", 316117], ["reflex", 316029], ["spectree", 316e3], ["remotezip2", 315997], ["html-void-elements", 315848], ["voluptuous-serialize", 315813], ["gallery-dl", 315783], ["pycocoevalcap", 315637], ["fcm-django", 315575], ["dumb-init", 315573], ["shot-scraper", 315528], ["torch-npu", 315469], ["apache-airflow-providers-hashicorp", 315322], ["mypy-boto3-timestream-query", 315187], ["apache-airflow-providers-atlassian-jira", 315183], ["google-cloud-bigquery-connection", 315102], ["freertos-gdb", 314895], ["airbyte-source-declarative-manifest", 314647], ["kmodes", 314594], ["tailscale", 314236], ["restate-sdk", 314187], ["otel-extensions", 314125], ["pyfunctional", 314074], ["mjml", 313990], ["dlipower", 313950], ["django-choices-field", 313915], ["propelauth-fastapi", 313598], ["vncdotool", 313303], ["cached-path", 313185], ["nova-act", 313066], ["openshift", 313010], ["semantic-kernel", 312867], ["arnparse", 312817], ["mypy-boto3-mwaa", 312784], ["opack2", 312782], ["pyobjc-framework-applicationservices", 312684], ["minijinja", 312488], ["esp-idf-monitor", 312402], ["toml-fmt-common", 312389], ["rlbot", 312373], ["robocorp-storage", 312186], ["asv-runner", 311743], ["awscliv2", 311619], ["nominal-streaming", 311562], ["pytest-pyodide", 311534], ["pims", 311496], ["code-review-graph", 311485], ["reflex-hosting-cli", 311398], ["multiset", 311328], ["py-sr25519-bindings", 311018], ["duo-client", 310375], ["sanic-cors", 310238], ["dask-image", 310236], ["flake8-cognitive-complexity", 310174], ["gnureadline", 309975], ["torch-complex", 309971], ["types-pyrfc3339", 309931], ["bzt", 309729], ["pylzss", 309708], ["glum", 309671], ["pyobjc-framework-coretext", 309283], ["repath", 309281], ["tabmat", 309166], ["banal", 308967], ["pytoml", 308955], ["django-jinja", 308918], ["mistralai-vibe-sdk", 308916], ["mkdocs-jupyter", 308867], ["types-tensorflow", 308835], ["django-zen-queries", 308685], ["pick", 308495], ["pydantic-ai-todo", 308396], ["ansible-dev-environment", 308207], ["types-boto3-bedrock", 308105], ["tensorrt-cu12-libs", 308045], ["seedir", 307995], ["pandas-read-xml", 307981], ["streamlit-pdf-viewer", 307961], ["npmai", 307923], ["mypy-boto3-mediaconvert", 307867], ["rpy2", 307513], ["splinter", 307227], ["shfmt-py", 307055], ["hurry-filesize", 306964], ["python-tss-sdk", 306705], ["pinecone-plugin-inference", 306668], ["opentelemetry-python-contrib-external-valkey", 306610], ["mypy-boto3-appsync", 306342], ["varint", 306255], ["orbax-export", 306240], ["azure-iot-device", 306194], ["simplejpeg", 306180], ["acryl-datahub-airflow-plugin", 305911], ["starsessions", 305770], ["icechunk", 305435], ["carelytics", 305339], ["mypy-boto3-elasticbeanstalk", 305288], ["lasio", 305058], ["skia-pathops", 304971], ["newton", 304922], ["python-speech-features", 304841], ["zcbor", 304632], ["purl", 304478], ["types-orjson", 304278], ["backports-cached-property", 304152], ["mozdevice", 304034], ["lazr-config", 303863], ["flufl-i18n", 303742], ["wadllib", 303739], ["python-dynamodb-lock", 303688], ["pyarmor-cli-core", 303583], ["pyobjc-framework-webkit", 303485], ["awacs", 303395], ["pytest-suite-timeout", 303366], ["gocardless-pro", 303231], ["mypy-boto3-codecommit", 303200], ["lightkube", 303077], ["clint", 302989], ["azureml-dataprep", 302925], ["args", 302896], ["textx", 302886], ["mypy-boto3-servicediscovery", 302812], ["heapdict", 302747], ["prospector", 302708], ["daily-python", 302622], ["apkutils2", 302561], ["django-bitfield", 302398], ["mailman", 302383], ["rpaframework", 302190], ["cigam", 302138], ["crick", 302058], ["sphinx-autodoc2", 302004], ["i18nice", 301965], ["cfgraph", 301849], ["logger", 301784], ["cmarkgfm", 301767], ["neo4j-graphrag", 301719], ["simplefix", 301629], ["sensai-utils", 301611], ["mypy-boto3-acm-pca", 301578], ["mojimoji", 301493], ["roboflow", 301317], ["pyzxing", 301084], ["mypy-boto3-amplify", 301008], ["mo-dots", 300923], ["python-jwt", 300786], ["lazr-restfulclient", 300749], ["pytest-pytestrail", 300730], ["openfeature-provider-flagd", 300727], ["tensorrt-cu12-bindings", 300307], ["protoc-gen-validate", 300211], ["substrait", 300156], ["rpaframework-core", 300148], ["postgres", 300142], ["pyx12", 300100], ["pyglove", 300054], ["google-maps-routing", 299910], ["wsgiref", 299874], ["mypy-boto3-verifiedpermissions", 299845], ["pyopengl-accelerate", 299797], ["pathtools", 299740], ["html2image", 299727], ["bump-pydantic", 299469], ["grequests", 299366], ["oslo-messaging", 299306], ["python-pkcs11", 299262], ["pluralizer", 299207], ["mode-streaming", 299204], ["mypy-boto3-resource-groups", 299159], ["conformer", 298885], ["spookyhash", 298748], ["janaf", 298668], ["pygeoif", 298651], ["spsdk-mcu-link", 298342], ["pyzipcode", 298328], ["pyobjc-framework-security", 298314], ["reasoning-gym", 298036], ["xacro", 297944], ["mypy-boto3-pinpoint", 297936], ["airflow-provider-fivetran-async", 297757], ["dynamic-yaml", 297499], ["databricks-feature-store", 297306], ["plotly-resampler", 297217], ["emrvalidator", 297197], ["skills-ref", 297177], ["jdk4py", 297141], ["kaldi-python-io", 297064], ["pytest-mock-resources", 296942], ["random-user-agent", 296920], ["cohere-compass-sdk", 296678], ["robotframework-sshlibrary", 296624], ["nevergrad", 296610], ["langchain-perplexity", 296585], ["rply", 296508], ["fluids", 296494], ["pulumi-confluentcloud", 296436], ["koyeb-sdk", 296327], ["pytest-structlog", 296305], ["ibm-quantum-schemas", 296208], ["nodriver", 296156], ["pygeodesy", 296077], ["portforward", 295933], ["mypy-boto3-glacier", 295898], ["attr", 295661], ["vale", 295577], ["mypy-boto3-serverlessrepo", 294999], ["kokoro", 294721], ["urlcanon", 294686], ["samplomatic", 294569], ["pytest-loguru", 294425], ["dm-control", 294342], ["stim", 294315], ["spsdk-pyocd", 294272], ["aiodebug", 294197], ["mypy-boto3-kinesisanalyticsv2", 294167], ["llama-index-vector-stores-chroma", 294125], ["mypy-boto3-pi", 293930], ["libcudf-cu12", 293875], ["pycolmap", 293859], ["alibabacloud-darabonba-signature-util", 293809], ["alibabacloud-darabonba-string", 293796], ["alibabacloud-darabonba-array", 293530], ["headroom-ai", 293371], ["m2crypto", 293356], ["pytest-mongo", 293245], ["mypy-boto3-kinesisanalytics", 293199], ["llama-index-llms-anthropic", 293177], ["alibabacloud-darabonba-map", 293102], ["pydantic-ai-shields", 292997], ["secure-smtplib", 292983], ["lovelyplots", 292971], ["python-logstash-async", 292848], ["fractional-indexing", 292711], ["lambdatest-selenium-driver", 292667], ["mypy-boto3-iotwireless", 292652], ["openupgradelib", 292505], ["pyroma", 292315], ["blaxel", 292177], ["mypy-boto3-codestar-connections", 292099], ["bounded-pool-executor", 291995], ["mypy-boto3-mq", 291806], ["voluptuous-openapi", 291697], ["alibabacloud-darabonba-encode-util", 291558], ["jax-cuda13-pjrt", 291522], ["mypy-boto3-managedblockchain", 291398], ["robotframework-seleniumtestability", 291338], ["ha-mcp", 291060], ["langchainplus-sdk", 290922], ["pyannotate", 290875], ["libvirt-python", 290738], ["mdformat-footnote", 290665], ["python-gflags", 290585], ["semantic-router", 290286], ["pyvips-binary", 289948], ["pycobertura", 289875], ["tensordict-nightly", 289698], ["numkong", 289518], ["deepdiff6", 289508], ["sdnotify", 289492], ["dagster-azure", 289486], ["twelvelabs", 289263], ["atlan-application-sdk-conformance", 289258], ["pykcs11", 289162], ["gluonts", 289087], ["mypy-boto3-cloudcontrol", 289065], ["aurelio-sdk", 288956], ["mlx-audio", 288906], ["oslo-db", 288774], ["pytest-httpx2", 288694], ["flake8-simplify", 288646], ["awkward-pandas", 288457], ["sphinx-llm", 288382], ["wiremock", 287896], ["openapi-codec", 287787], ["email-to", 287761], ["free-proxy", 287661], ["rpaframework-pdf", 287572], ["mxnet", 287452], ["oic", 287361], ["opentelemetry-exporter-zipkin-json", 287347], ["readline", 287330], ["mobly", 287236], ["session-info", 287155], ["pyprojroot", 287148], ["pyartifactory", 287124], ["google-ads-admanager", 287076], ["authcaptureproxy", 287075], ["graphlib-backport", 286964], ["mkdocs-llmstxt", 286756], ["memcache-hybrid", 286670], ["colour-science", 286603], ["githubkit-schemas-2026-03-10", 286508], ["mypy-boto3-elb", 286413], ["azure-mgmt-kusto", 286350], ["konoha", 286318], ["pyscf", 286312], ["pytest-textual-snapshot", 286309], ["pubnub", 286272], ["mypy-boto3-pipes", 286260], ["fhirclient", 285857], ["githubkit-schemas", 285722], ["alt-profanity-check", 285584], ["lagom", 285454], ["pyteomics", 285451], ["pgzip", 285443], ["mypy-boto3-codeconnections", 285427], ["django-filter-stubs", 285317], ["filecheck", 285137], ["pymupdf-fonts", 285118], ["delayed-assert", 284904], ["libcuml-cu12", 284787], ["pyoxigraph", 284640], ["delvewheel", 284559], ["zep-cloud", 284554], ["chromedriver-autoinstaller", 284532], ["apache-airflow-providers-apache-livy", 284468], ["healpy", 284210], ["sglang-router", 283983], ["nvidia-modelopt", 283979], ["openlit", 283978], ["path-py", 283966], ["pqdm", 283701], ["liquidpy", 283485], ["pytest-tornasync", 283465], ["airflow-clickhouse-plugin", 283220], ["pinecone-text", 283164], ["simple-pid", 282994], ["python-fcl", 282938], ["ngcsdk", 282877], ["bravado-core", 282643], ["pysnc", 282611], ["directsearch", 282607], ["django-bootstrap3", 282537], ["funasr", 282378], ["django-zeal", 282290], ["dnfile", 282224], ["mozinfo", 282103], ["graphene-file-upload", 281774], ["reflex-base", 281766], ["altcha", 281716], ["lazr-delegates", 281701], ["pyeapi", 281614], ["pyventus", 281594], ["ascii-magic", 281551], ["types-aiobotocore-dataexchange", 281505], ["nvidia-riva-client", 281386], ["aiodynamo", 281321], ["fernet", 281190], ["pdb-attach", 281144], ["rasa-sdk", 281102], ["scc-firewall-manager-sdk", 280896], ["durabletask", 280790], ["klaviyo-api", 280644], ["django-grappelli", 280590], ["rouge-metric", 280559], ["dash-extensions", 280533], ["xero-python", 280509], ["cassetter", 280464], ["mercadopago", 280448], ["pybloom-live", 280356], ["opuslib", 280251], ["aws-durable-execution-sdk-python", 280248], ["zernio-sdk", 280209], ["aider-chat", 280173], ["untangle", 280160], ["onnxruntime-openvino", 280048], ["ttp", 279980], ["langchain-milvus", 279901], ["json-spec", 279861], ["xmldiff", 279645], ["cwsandbox", 279604], ["getmac", 279490], ["flask-apscheduler", 279306], ["pytest-loop", 279138], ["nptdms", 279086], ["pytest-pythonpath", 278876], ["vt-py", 278875], ["pdfrw2", 278825], ["mrcfile", 278810], ["oslo-middleware", 278803], ["textract", 278800], ["ipyevents", 278766], ["onnx-graphsurgeon", 278637], ["pypd", 278608], ["pyobjc-framework-coreml", 278526], ["detect-delimiter", 278506], ["gigatoken", 278504], ["py-trees", 278415], ["e2b-desktop", 278390], ["a2ui-core", 278241], ["lalsuite", 278138], ["pydomo", 278065], ["cocotb-bus", 278062], ["objectory", 277968], ["cmake-format", 277922], ["google-maps-addressvalidation", 277802], ["pyobjc-framework-vision", 277790], ["spin", 277598], ["fabric-cicd", 277479], ["lseg-data", 277387], ["pytorch-msssim", 277384], ["editdistpy", 277341], ["instagrapi", 277214], ["pysonar", 277193], ["file-read-backwards", 277120], ["types-boto3-ssm", 276986], ["gethwp", 276970], ["awslabs-aws-api-mcp-server", 276914], ["sarif-tools", 276847], ["factur-x", 276724], ["valkey-glide-sync", 276690], ["ultimate-sitemap-parser", 276688], ["arelle-release", 276624], ["microsoft-agents-copilotstudio-client", 276470], ["python-docx-ml6", 276445], ["oslo-policy", 276375], ["arcadepy", 276183], ["imgui-bundle", 276093], ["symengine", 276078], ["phonetics", 276075], ["mypy-boto3-sso", 276026], ["flask-executor", 275949], ["scikit-plot", 275949], ["redis-sentinel-url", 275876], ["awsebcli", 275713], ["sshfs", 275672], ["pamela", 275527], ["gdsfactory", 275392], ["django-braces", 275383], ["webexpythonsdk", 275381], ["pyproject-flake8", 275238], ["jax-cuda13-plugin", 274605], ["mozprocess", 274409], ["docx2python", 274234], ["tentaclio-postgres", 273972], ["pydynamodb", 273960], ["spotipy", 273947], ["rdiff", 273923], ["graphlib", 273690], ["livekit-plugins-azure", 273636], ["xdsl", 273501], ["agent-framework-devui", 273310], ["prefect-dbt", 273230], ["chameleon", 273030], ["java-access-bridge-wrapper", 273004], ["multi-storage-client", 272986], ["google-cloud-appengine-admin", 272956], ["kiwipiepy-model", 272556], ["rq-dashboard", 272508], ["librmm-cu12", 272436], ["noisereduce", 272095], ["vonage", 272093], ["sagemaker-inference", 271878], ["linkup-sdk", 271781], ["flet", 271498], ["icontract", 271481], ["s3tokenizer", 271377], ["podman-compose", 271310], ["tdda", 271219], ["spsdk", 271144], ["cdp", 271131], ["dagit", 271053], ["ray-haproxy", 271035], ["google-oauth", 270990], ["flask-oauthlib", 270893], ["launchpadlib", 270868], ["django-cotton", 270821], ["jsonslicer", 270788], ["celery-once", 270556], ["bitmath", 270523], ["nvidia-libnvcomp-cu12", 270162], ["astpretty", 270153], ["durabletask-azuremanaged", 270134], ["rmm-cu12", 270043], ["pyvex", 269985], ["pyrogram", 269922], ["titiler-core", 269912], ["emmet-core", 269752], ["ordereddict", 269750], ["mkdocs-exclude", 269652], ["pdftext", 269153], ["django-revproxy", 269136], ["audiomentations", 268943], ["pytubefix", 268865], ["cudf-cu12", 268831], ["access-parser", 268807], ["baostock", 268804], ["argostranslate", 268745], ["pyobjc-framework-uniformtypeidentifiers", 268593], ["oslo-service", 268527], ["tftpy", 268461], ["django-classy-tags", 268435], ["chemicals", 268104], ["cityhash", 267986], ["plivo", 267947], ["adam-atan2-pytorch", 267918], ["typed-argument-parser", 267584], ["mercurial", 267544], ["peakrdl-html", 267537], ["pytest-filter-subpackage", 267516], ["pywikibot", 267308], ["osprofiler", 267230], ["singlestoredb", 267194], ["openhands-ai", 267107], ["superqt", 267097], ["onyx-devtools", 267067], ["edlib", 266975], ["streamlit-extras", 266774], ["mailchecker", 266689], ["pylibcudf-cu12", 266673], ["pytapo", 266620], ["rasterstats", 266548], ["pycti", 266361], ["slackify-markdown", 266284], ["fhconfparser", 266268], ["pymonetdb", 266201], ["fluent-pygments", 266103], ["sanic-jwt", 266066], ["openpyxl-stubs", 265981], ["django-sesame", 265970], ["peakrdl-cheader", 265910], ["libkvikio-cu12", 265908], ["django-seal", 265838], ["linear-tsv", 265722], ["openmeteo-sdk", 265644], ["cuml-cu12", 265541], ["types-toposort", 265508], ["optimistix", 265491], ["pptx2md", 265455], ["pyagrum-nightly", 265356], ["angr", 265347], ["mcp-clickhouse", 265325], ["ff3", 265319], ["robotframework-stacktrace", 265187], ["latex2sympy2", 265072], ["requests-ntlm3", 264926], ["pathwaysutils", 264883], ["tb-nightly", 264870], ["simhash", 264861], ["arn", 264860], ["torchtune", 264828], ["classify-imports", 264651], ["libraft-cu12", 264551], ["pytest-timestamper", 264525], ["rsl-rl-lib", 264440], ["dash-mantine-components", 264376], ["sagemaker-training", 264278], ["eyes-selenium", 264252], ["p4python", 264071], ["mmhash3", 263908], ["fbmessenger", 263435], ["speedtest-cli", 263406], ["browserstack-local", 263373], ["pynmeagps", 263331], ["pyvalid", 263323], ["click-configfile", 263318], ["awsglue-dev", 263315], ["composio-langchain", 263158], ["vonage-jwt", 262864], ["dom-toml", 262786], ["pyrad", 262739], ["certipy", 262650], ["trie", 262617], ["jupyterhub", 262602], ["auth0-api-python", 262592], ["git-me-the-url", 262562], ["sparse-dot-topn", 262438], ["azure-iot-hub", 262371], ["eyes-common", 262351], ["pytest-spec", 262304], ["microsoft-agents-hosting-teams", 262260], ["msgraph-beta-sdk", 262254], ["model-mommy", 262174], ["slack-discovery-sdk", 262143], ["httpbin", 262087], ["pytransform3d", 262052], ["clvm-rs", 261834], ["aws-cdk-aws-redshift-alpha", 261822], ["pyuwsgi", 261740], ["sure", 261727], ["clvm-tools-rs", 261653], ["types-maxminddb", 261600], ["wincertstore", 261570], ["govuk-bank-holidays", 261479], ["minidump", 261402], ["tushare", 261366], ["bluezoo", 261305], ["edk2-pytool-library", 260966], ["autogluon-core", 260867], ["pydriller", 260867], ["pygelf", 260475], ["fissix", 260424], ["python-ffmpeg", 260300], ["python-intercom", 260299], ["numpy-minmax", 260224], ["pytest-arraydiff", 260214], ["uiautomation", 259934], ["streamlit-folium", 259877], ["autogluon-features", 259853], ["mypy-boto3-bedrock-agent-runtime", 259704], ["semantic-text-splitter", 259681], ["mattermostwrapper", 259570], ["pproxy", 259548], ["sphinx-jsonschema", 259342], ["robotframework-databaselibrary", 259258], ["tensorrt", 259201], ["numpy-rms", 259165], ["td-client", 259155], ["runai-model-streamer-s3", 259063], ["mypy-boto3-dax", 259002], ["azure-communication-sms", 258943], ["textual-image", 258890], ["pylibraft-cu12", 258763], ["missingno", 258734], ["django-graphql-jwt", 258590], ["volcengine", 258554], ["gpsoauth", 258514], ["urlobject", 258439], ["amazoncaptcha", 258389], ["py3dmol", 258370], ["iapws", 258369], ["squareup", 258222], ["autogluon-tabular", 258051], ["robotframework-datadriver", 257694], ["venv-pack", 257529], ["geoarrow-types", 257489], ["grpcio-observability", 257448], ["yagmail", 257412], ["agent-framework-ag-ui", 257062], ["ripgrep", 257019], ["onigurumacffi", 256968], ["mkdocs-git-authors-plugin", 256874], ["django-cache-memoize", 256739], ["paragraphs", 256711], ["django-sortedm2m", 256451], ["nvitop", 256330], ["pypdftk", 256318], ["labmaze", 256264], ["polars-runtime-compat", 255926], ["aggdraw", 255693], ["libigl", 255556], ["dagster-datadog", 255552], ["python-path", 255547], ["color-matcher", 255461], ["python-stretch", 255426], ["django-admin-tools", 255425], ["pymunk", 255421], ["prefect-slack", 255390], ["brevo-python", 255233], ["thermo", 255218], ["tos", 255192], ["sqlcipher3", 255147], ["retry-requests", 255136], ["gigachat", 254950], ["griffe-pydantic", 254896], ["pyclamd", 254892], ["backports-entry-points-selectable", 254412], ["mo-future", 254321], ["pismosendlogs", 254318], ["appdynamics", 254296], ["ixnetwork-restpy", 254292], ["livekit-plugins-groq", 254264], ["tm1py", 254250], ["pyathenajdbc", 254196], ["agent-framework-orchestrations", 254175], ["overpunch", 254044], ["saspy", 253988], ["pulumi-eks", 253817], ["google-cloud-datacatalog-lineage", 253713], ["jose", 253698], ["libusbsio", 253496], ["parallel-ssh", 253484], ["setoptconf-tmp", 253406], ["djangorestframework-jsonapi", 253379], ["pyworld", 253378], ["aiomonitor", 253334], ["autoscraper", 253273], ["python-olm", 253257], ["astrapy", 253231], ["s3torchconnectorclient", 253079], ["tomlrt", 253004], ["types-mysqlclient", 252891], ["genbadge", 252599], ["apache-airflow-providers-elasticsearch", 252534], ["pyramid-tm", 252473], ["tombi", 252440], ["cloudsmith-api", 252409], ["pyston", 252182], ["uptime", 252051], ["neotime", 251828], ["google-maps-geocode", 251721], ["git-dumper", 251476], ["chacha20poly1305-reuseable", 251379], ["azureml-dataprep-native", 251318], ["sanic-testing", 251304], ["types-seaborn", 251265], ["streamlit-javascript", 251031], ["databricks-zerobus-ingest-sdk", 250780], ["pyangbind", 250756], ["ansible-navigator", 250723], ["placebo", 250716], ["pyston-autoload", 250675], ["mo-imports", 250653], ["genanki", 250637], ["pulumiverse-grafana", 250552], ["cryptg", 250533], ["mmengine", 250454], ["jdatetime", 250418], ["reflex-components-core", 250341], ["greenery", 250274], ["prefect-ray", 249997], ["pycowsay", 249954], ["googlenewsdecoder", 249875], ["yarn-api-client", 249771], ["barcodenumber", 249716], ["azure-messaging-webpubsubservice", 249638], ["django-migrations-git-conflicts", 249473], ["http-sf", 249469], ["pypydispatcher", 249318], ["byteplus-python-sdk-v2", 249215], ["feast", 249207], ["mdxpy", 249200], ["abxbus", 249141], ["click-command-tree", 249106], ["hip-python", 249005], ["structlog-config", 248861], ["mkdocs-swagger-ui-tag", 248707], ["bigquery", 248670], ["mastodon-py", 248577], ["robotframework-excellib", 248525], ["pyvistaqt", 248153], ["django-template-partials", 248035], ["pydantic-partial", 247994], ["azure-communication-identity", 247981], ["python-ripgrep", 247767], ["django-admin-logs", 247635], ["openmeteo-requests", 247631], ["pynng", 247463], ["overloading", 247249], ["kfactory", 247086], ["mlx-vlm", 247064], ["pyrtf3", 247064], ["pytest-html-merger", 247026], ["cogapp", 246959], ["pytest-cpp", 246925], ["pytest-astropy-header", 246850], ["point-cloud-utils", 246810], ["oslo-cache", 246763], ["django-sequences", 246727], ["grpc-gateway-protoc-gen-openapiv2", 246480], ["traits", 246478], ["azureml-dataprep-rslex", 246465], ["subagents-pydantic-ai", 246332], ["resemblyzer", 246284], ["allpairspy", 246231], ["flask-cognito", 246053], ["pdfminer", 246052], ["autogluon-common", 246038], ["flask-security-too", 245974], ["ansicon", 245896], ["reflex-components-lucide", 245762], ["django-dramatiq", 245716], ["klujax", 245713], ["sqlalchemy-databricks", 245700], ["oslo-metrics", 245687], ["conditional", 245627], ["django-fixture-magic", 245586], ["types-gunicorn", 245533], ["pytest-playwright-visual-snapshot", 245480], ["workspace-mcp", 245191], ["drf-flex-fields", 245079], ["ssh-python", 245073], ["rapidata", 245048], ["peakrdl-regblock", 244948], ["async-cache", 244837], ["tailer", 244810], ["mypy-boto3-greengrassv2", 244790], ["appdynamics-bindeps-linux-x64", 244766], ["aplr", 244723], ["pycoingecko", 244645], ["ruamel-yaml-string", 244631], ["mypy-boto3-lambda-microvms", 244613], ["flake8-requirements", 244562], ["basicsr", 244529], ["pyromark", 244458], ["types-aiobotocore-kinesis", 244440], ["keystonemiddleware", 244258], ["maxminddb-geolite2", 244235], ["wlc", 244217], ["kml2geojson", 243826], ["flake8-variables-names", 243790], ["zuban", 243760], ["onnx2torch", 243746], ["zope-proxy", 243614], ["drake", 243419], ["appdynamics-proxysupport-linux-x64", 243329], ["json5kit", 243317], ["tangled-up-in-unicode", 243256], ["prov", 243239], ["vonage-utils", 243061], ["secops", 242873], ["kiteconnect", 242790], ["massive", 242558], ["prefect-snowflake", 242534], ["pytest-astropy", 242376], ["sqlalchemy-cloudflare-d1", 242320], ["sb3-contrib", 242269], ["benchling-api-client", 242036], ["cassio", 241912], ["openfeature-provider-ofrep", 241772], ["eth-bloom", 241707], ["pdfservices-sdk", 241578], ["nutter", 241489], ["pytestarch", 241360], ["sift", 241235], ["morefs", 241217], ["uv-sort", 241115], ["s3torchconnector", 241016], ["fugue-sql-antlr", 240964], ["orion-py-client", 240907], ["stem", 240848], ["pyzabbix", 240811], ["sax", 240712], ["sphinxcontrib-confluencebuilder", 240473], ["google-cloud-mldiagnostics", 240460], ["sqlalchemy-schemadisplay", 240460], ["fastapi-restful", 240382], ["inspect-scout", 240182], ["ansible-creator", 240178], ["chromadb-client", 240075], ["sec-edgar-downloader", 240039], ["lerobot", 240028], ["motor-types", 239795], ["minisbd", 239754], ["hcloud", 239731], ["rasa", 239575], ["pyformance", 239513], ["sphinx-jinja", 239451], ["pystack", 239366], ["multiaddr", 239231], ["kafka", 239184], ["hachoir", 239054], ["pykrx", 239053], ["speechmatics-rt", 239031], ["numbagg", 238969], ["django-mock-queries", 238857], ["implicit", 238776], ["python-librsync", 238764], ["harness-featureflags", 238763], ["fillpdf", 238679], ["pycadf", 238678], ["jmp", 238670], ["biothings-client", 238593], ["django-recurrence", 238548], ["reducto", 238437], ["mautrix", 238428], ["adtk", 238380], ["pykmip", 238192], ["django-clone", 238126], ["pytest-plugin-utils", 238096], ["cf-xarray", 238045], ["cachy", 237991], ["envparse", 237746], ["qutip", 237725], ["seqlog", 237691], ["pesq", 237686], ["utf-queue-client", 237609], ["fastapi-profiler", 237455], ["summarization-pydantic-ai", 237403], ["colorzero", 237332], ["microsoft-agents-hosting-aiohttp", 237311], ["r7insight-python", 237126], ["esp-idf-nvs-partition-gen", 237064], ["intel-cmplr-lib-rt", 236981], ["rapidyaml", 236974], ["scaleway", 236892], ["pytest-xdist-worker-stats", 236806], ["pydeseq2", 236800], ["apswutils", 236774], ["python-sonarqube-api", 236738], ["vocos", 236731], ["types-boto3-bedrock-agent", 236595], ["reflex-components-sonner", 236543], ["fastlite", 236456], ["libsast", 236380], ["favicon", 236307], ["awxkit", 236226], ["antsibull-docs-parser", 236150], ["captcha", 236086], ["antsibull-fileutils", 235703], ["aiogithubapi", 235686], ["python-gerrit-api", 235634], ["optimum-quanto", 235542], ["types-boto3-sagemaker-runtime", 235540], ["aiojobs", 235484], ["airbyte-protocol-models-pdv2", 235214], ["django-extra-views", 235084], ["pymysqllock", 235080], ["tensorrt-cu13", 235058], ["extend-ai", 234994], ["tf-nightly", 234958], ["pagefind", 234901], ["binpacking", 234698], ["pycaret", 234654], ["sodapy", 234514], ["mo-parsing", 234412], ["gpiozero", 234383], ["vonage-messages", 234348], ["mypy-boto3-bedrock-agent", 234217], ["scikit-learn-stubs", 234205], ["bigframes", 234187], ["diffrax", 234171], ["vonage-video", 234121], ["torcheval", 234112], ["pulumi-policy", 233963], ["py2neo-history", 233955], ["english", 233920], ["pgspecial", 233735], ["quantities", 233732], ["junos-eznc", 233717], ["yake", 233691], ["pylibftdi", 233603], ["peakrdl", 233515], ["jsonc-parser", 233451], ["t61codec", 233398], ["pytest-localserver", 233333], ["toolbox-adk", 233330], ["agentscope", 233320], ["markdown-include", 233293], ["cirq-core", 233272], ["core-universal", 233167], ["tml-renderers", 233102], ["scrypt", 233049], ["optuna-dashboard", 232925], ["sphinxcontrib-napoleon", 232854], ["onnxoptimizer", 232746], ["pgcli", 232744], ["agate-sql", 232703], ["tableschema", 232600], ["laya", 232238], ["django-push-notifications", 232182], ["mygene", 232143], ["igittigitt", 232118], ["django-hashid-field", 232053], ["cloudant", 232051], ["owslib", 231988], ["statistics", 231958], ["django-datadog-logger", 231933], ["gibberish-detector", 231907], ["instaloader", 231858], ["pockets", 231841], ["numpy-groupies", 231760], ["vonage-http-client", 231746], ["sqlalchemy-dremio", 231684], ["apache-airflow-providers-apache-beam", 231489], ["semver4", 231409], ["dilithium-py", 231330], ["geoip2fast", 231223], ["alibabacloud-gateway-pop", 231180], ["rake-nltk", 231047], ["wecom-aibot-python-sdk", 231030], ["snowflake-ml-python", 230994], ["types-pyperclip", 230980], ["vonage-voice", 230964], ["faust-streaming", 230930], ["tkinterdnd2", 230904], ["sib-api-v3-sdk", 230900], ["hstspreload", 230897], ["livy", 230794], ["samplerate", 230676], ["flake8-logging-format", 230614], ["vonage-verify", 230608], ["vonage-users", 230593], ["vonage-account", 230540], ["vonage-sms", 230534], ["vonage-application", 230529], ["python-dxf", 230467], ["vonage-verify-legacy", 230420], ["raindrop-ai", 230319], ["flask-apispec", 230277], ["pydantic-to-pyarrow", 230238], ["agate-excel", 230206], ["types-zstd", 230167], ["pyuvm", 230045], ["django-sekizai", 229951], ["vonage-numbers", 229839], ["joblibspark", 229816], ["csvkit", 229794], ["scrapfly-sdk", 229691], ["vonage-number-insight", 229600], ["vonage-network-auth", 229580], ["vonage-network-number-verification", 229561], ["pyiqa", 229560], ["vonage-subaccounts", 229553], ["vonage-network-sim-swap", 229550], ["unittest-parametrize", 229446], ["mypy-boto3-service-quotas", 229419], ["django-mcp-server", 229283], ["utils", 229275], ["django-admin-interface", 229253], ["cocotb-test", 229235], ["pydap", 229216], ["llama-index-vector-stores-qdrant", 228939], ["imgcat", 228785], ["newspaper4k", 228750], ["pyexecjs", 228747], ["pytd", 228421], ["scipy-openblas32", 228387], ["inertia-django", 228360], ["pyvrp", 228323], ["laboratory", 228142], ["openmm", 228073], ["ansible-dev-tools", 227912], ["omnibase-infra", 227587], ["torchx", 227551], ["agate-dbf", 227511], ["energyquantified", 227391], ["gem-llm", 227348], ["types-aiobotocore-full", 227213], ["mocket", 227211], ["aws-cdk-aws-neptune-alpha", 227146], ["aws-mfa-v2", 227047], ["pytest-tagging", 227023], ["django-bootstrap4", 227017], ["pyglm", 226967], ["ipadic", 226847], ["types-channels", 226839], ["wtforms-json", 226829], ["python-ipmi", 226647], ["x690", 226557], ["can-isotp", 226476], ["juju", 226454], ["stirrup", 226255], ["cpe", 226249], ["pettingzoo", 226187], ["livekit-plugins-soniox", 226109], ["oslo-upgradecheck", 226095], ["ansible-sign", 225888], ["fasttext-langdetect", 225648], ["msg-parser", 225604], ["sphinx-needs", 225591], ["stopit", 225588], ["runwayml", 225556], ["static-ffmpeg", 225456], ["inquirer3", 225418], ["cn2an", 225402], ["pulumi-databricks", 225337], ["spark-parser", 225337], ["pipupgrade", 225295], ["unified-python-sdk", 225265], ["geoarrow-c", 225156], ["sttable", 225128], ["pytest-json", 225052], ["ubai-client", 224979], ["jupyter-http-over-ws", 224935], ["sslpsk-pmd3", 224927], ["zope-deferredimport", 224855], ["ip2location", 224840], ["django-chunkator", 224816], ["requests-sse", 224815], ["workers-runtime-sdk", 224791], ["pulumi-azure", 224757], ["janome", 224742], ["djangorestframework-datatables", 224727], ["benchling-sdk", 224723], ["jinja2-pluralize", 224607], ["deskew", 224533], ["python-neutronclient", 224497], ["mermaid-builder", 224479], ["llama-index-llms-openai-like", 224442], ["deepseek-harness-runtime-bin", 224435], ["esp-idf-panic-decoder", 224201], ["mailchimp3", 224164], ["pytest-twisted", 224036], ["blurhash", 224010], ["reflex-components-radix", 223887], ["onemkl-license", 223800], ["tnefparse", 223794], ["wfdb", 223752], ["bittensor", 223749], ["ipython-sql", 223668], ["logging-tree", 223520], ["stac-pydantic", 223394], ["slh-dsa", 223311], ["sphinxcontrib-openapi", 223293], ["bravado", 223284], ["neptune-query", 223219], ["sap-ai-sdk-gen", 223184], ["hydra-colorlog", 223122], ["crochet", 223109], ["elasticsearch-curator", 223076], ["acceldata-sdk", 223047], ["requests-hardened", 223026], ["varname", 222876], ["langchain-oracledb", 222845], ["ast-comments", 222798], ["aws-shell", 222709], ["rfdetr", 222611], ["amazon-sqs-extended-client", 222593], ["django-jsoneditor", 222591], ["jalali-core", 222495], ["akeyless-cloud-id", 222389], ["hol-guard", 222296], ["pytest-antilru", 222157], ["shamir-mnemonic", 222057], ["pynetdicom", 222026], ["shiny", 221985], ["ormar", 221915], ["proto-schema-parser", 221853], ["nab-python", 221773], ["scour", 221723], ["cuequivariance", 221664], ["async-factory-boy", 221583], ["bpyutils", 221521], ["salesforce-api", 221481], ["baron", 221453], ["piq", 221405], ["django-google-sso", 221288], ["python-glanceclient", 221157], ["cybrid-api-organization-python", 221094], ["aiven-client", 221012], ["webapp2", 220965], ["django-crontab", 220939], ["cchecksum", 220842], ["prefect-dask", 220813], ["ceja", 220798], ["exactextract", 220753], ["manygo", 220692], ["fileseq", 220645], ["rush", 220641], ["openinference-instrumentation-bedrock", 220502], ["streamlit-agraph", 220395], ["asdf", 220281], ["potracer", 220266], ["testmuai-selenium-bindings", 220129], ["jws", 220094], ["pyodide-py", 220038], ["redbaron", 219818], ["citeurl", 219769], ["vicinity", 219654], ["wsgidav", 219638], ["pytenable", 219631], ["django-multitenant", 219563], ["okonomiyaki", 219550], ["fuzzyset2", 219356], ["ansys-tools-common", 219327], ["dtw-python", 219302], ["dataflows-tabulator", 219241], ["aiometer", 219205], ["gspread-asyncio", 219198], ["runai-model-streamer-gcs", 219125], ["apache-airflow-providers-github", 219101], ["apache-airflow-providers-apache-druid", 219066], ["pyuca", 218927], ["pytest-integration", 218871], ["eppo-server-sdk", 218852], ["django-registration", 218804], ["ml-goodput-measurement", 218712], ["django-fast-update", 218545], ["lorem", 218539], ["reflex-components-code", 218531], ["django-querycount", 218501], ["agent-framework-anthropic", 218437], ["agent-framework-durabletask", 218410], ["drjit", 218265], ["sphinx-data-viewer", 218148], ["django-render-block", 218124], ["xkcdpass", 218113], ["pyclibrary", 217938], ["dockerfile", 217882], ["vrplib", 217733], ["googleauthentication", 217624], ["shiv", 217563], ["rst2ansi", 217547], ["warlock", 217491], ["simplesat", 217465], ["azure-mgmt-managedservices", 217412], ["tslearn", 217351], ["pandavro", 217293], ["agent-framework-a2a", 217280], ["bpemb", 217250], ["observable", 217218], ["mechanize", 217200], ["cerbos", 217080], ["pyfzf", 217075], ["tensorrt-cu13-libs", 217062], ["django-cachalot", 216741], ["type-enforced", 216704], ["pdfid", 216630], ["pyreadr", 216453], ["pynvim", 216451], ["html-testrunner", 216371], ["unitypy", 216345], ["hatch-polylith-bricks", 216344], ["astropy-healpix", 216287], ["packaging-legacy", 216275], ["scrapeops-scrapy-proxy-sdk", 216275], ["sphinxext-rediraffe", 216129], ["brazilnum", 216051], ["scrapy-stealth", 215996], ["glean-parser", 215935], ["scrapy-ingest", 215835], ["dbstream", 215813], ["webassets", 215800], ["pytest-redis", 215744], ["pyunpack", 215709], ["pretend", 215692], ["scaleway-core", 215599], ["keras-nightly", 215595], ["percentify", 215550], ["pyre-check", 215226], ["bddl", 215106], ["prompty", 215086], ["molecule-docker", 214938], ["thespian", 214914], ["expects", 214862], ["django-nose", 214855], ["pyreqwest", 214790], ["django-rest-swagger", 214737], ["sdmx1", 214734], ["drjax", 214719], ["circus", 214631], ["tensorflow-io", 214598], ["textual-plotext", 214470], ["types-sqlalchemy", 214424], ["x25519", 214318], ["mypy-boto3-s3files", 214291], ["gcloud-aio-datastore", 214248], ["spacy-transformers", 214214], ["pylibmagic", 214179], ["streamingjson", 214161], ["firebird-base", 214116], ["fiscalyear", 214104], ["firebird-driver", 213913], ["simplification", 213849], ["django-haystack", 213693], ["vsdx", 213683], ["fastdownload", 213617], ["doublemetaphone", 213588], ["socketdev", 213520], ["encord", 213307], ["weblate-fonts", 213131], ["ipydagred3", 213129], ["apache-airflow-providers-sendgrid", 213006], ["solc-select", 212941], ["pyautogen", 212749], ["picobox", 212676], ["pygrib", 212648], ["meltanolabs-target-snowflake", 212628], ["nfoursid", 212580], ["mp-api", 212577], ["reflex-components-plotly", 212507], ["more-click", 212485], ["times", 212424], ["django-contrib-comments", 212225], ["coverage-threshold", 212162], ["htbuilder", 212137], ["ucumvert", 212127], ["django-viewflow", 212092], ["pyreadline", 212071], ["ws4py", 212057], ["slugify", 212053], ["jupyter-book", 211993], ["pyfcm", 211911], ["ruamel-base", 211840], ["types-aiobotocore-bedrock", 211764], ["celery-batches", 211716], ["plexapi", 211608], ["fastkml", 211546], ["apache-superset-core", 211289], ["pyrealsense2", 211269], ["paracelsus", 211211], ["os-testr", 210970], ["py-evm", 210865], ["notify-py", 210817], ["reflex-components-recharts", 210797], ["pinterest-api-sdk", 210761], ["starlette-admin", 210747], ["django-sql-explorer", 210730], ["atheris", 210456], ["phonopy", 210406], ["pinterest-generated-client", 210404], ["java-manifest", 210365], ["construct-classes", 210266], ["lucopy", 210261], ["sphinxcontrib-programoutput", 210096], ["blkinfo", 210035], ["tsfresh", 209945], ["marketorestpython", 209935], ["demoji", 209825], ["openlineage-dbt", 209787], ["gdtoolkit", 209698], ["gspread-pandas", 209612], ["steel-sdk", 209592], ["pip-check", 209502], ["ldfparser", 209424], ["mitsuba", 209383], ["writer-sdk", 209248], ["aiomcache", 209141], ["qdk", 209111], ["iso-week-date", 209094], ["fal", 208979], ["parquet", 208970], ["unicon", 208867], ["cloud-accelerator-diagnostics", 208768], ["netutils", 208724], ["reflex-components-dataeditor", 208692], ["depthai", 208686], ["google-cloud-bigquery-reservation", 208658], ["opendal", 208460], ["reka-api", 208276], ["rtp", 208234], ["pdbeccdutils", 208227], ["torch-tb-profiler", 208202], ["taskiq-fastapi", 208156], ["mdformat-mkdocs", 208131], ["django-guid", 208124], ["dearpygui", 207820], ["fuzzyfinder", 207791], ["cocotb-coverage", 207769], ["flake8-pyi", 207761], ["reflex-components-react-player", 207743], ["scan-build", 207736], ["gecosistema-lite", 207676], ["cybrid-api-id-python", 207598], ["kaldifst", 207573], ["mmtf-python", 207521], ["deepseek-harness-sdk", 207372], ["rhino3dm", 207313], ["pydes", 207311], ["aiodogstatsd", 207265], ["yamlloader", 207082], ["django-dbbackup", 207069], ["deadcode", 207066], ["libuuu", 207063], ["testcontainers-core", 207039], ["google-cloud-common", 207011], ["reflex-components-gridjs", 206964], ["lambdapdk", 206960], ["llama-index-retrievers-bm25", 206954], ["actions-toolkit", 206851]] };

// packages/core/src/intel/popular.ts
var CRYPTO_NPM = [
  "ethers",
  "web3",
  "viem",
  "wagmi",
  "@solana/web3.js",
  "@solana/spl-token",
  "@solana/kit",
  "@coral-xyz/anchor",
  "@project-serum/anchor",
  "ccxt",
  "@polymarket/client",
  "@polymarket/clob-client",
  "@polymarket/clob-client-v2",
  "@polymarket/order-utils",
  "polymarket-us",
  "@uniswap/sdk-core",
  "@uniswap/v2-sdk",
  "@uniswap/v3-sdk",
  "@uniswap/universal-router-sdk",
  "bignumber.js",
  "bn.js",
  "big.js",
  "decimal.js",
  "@jup-ag/api",
  "@raydium-io/raydium-sdk-v2",
  "@pythnetwork/client",
  "@openzeppelin/contracts",
  "@chainlink/contracts",
  "hardhat",
  "@nomicfoundation/hardhat-toolbox",
  "dotenv",
  "axios",
  "node-fetch",
  "ws",
  "telegraf",
  "node-telegram-bot-api",
  "grammy",
  "discord.js",
  "@binance/connector",
  "binance-api-node",
  "node-binance-api",
  "@metamask/sdk",
  "@coinbase/coinbase-sdk",
  "@coinbase/cdp-sdk",
  "@nktkas/hyperliquid",
  "hyperliquid",
  "technicalindicators",
  "trading-signals",
  "@anthropic-ai/sdk",
  "@anthropic-ai/claude-agent-sdk",
  "openai",
  "bs58",
  "tweetnacl",
  "@noble/hashes",
  "@noble/curves",
  "@scure/bip39",
  "bip39",
  "ethereumjs-util"
];
var CRYPTO_PYPI = [
  "polymarket-client",
  "py-clob-client",
  "py-clob-client-v2",
  "polymarket-us",
  "web3",
  "eth-account",
  "ccxt",
  "python-binance",
  "binance-connector",
  "solana",
  "solders",
  "anchorpy",
  "hyperliquid-python-sdk",
  "freqtrade",
  "requests",
  "python-dotenv",
  "websockets",
  "aiohttp",
  "pandas",
  "numpy",
  "ta",
  "backtrader",
  "vectorbt",
  "python-telegram-bot",
  "anthropic",
  "openai",
  "eth-utils",
  "eth-abi",
  "coinbase-advanced-py",
  "kalshi-python",
  "py-order-utils",
  "pycryptodome",
  "base58",
  "mnemonic",
  "bip-utils"
];
function canonicalPypi(name) {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}
var npmNames = [.../* @__PURE__ */ new Set([...CRYPTO_NPM, ...popular_npm_default.names])];
var pypiRows = popular_pypi_default.rows;
var pypiDownloads = /* @__PURE__ */ new Map();
for (const [name, count] of pypiRows) pypiDownloads.set(canonicalPypi(name), count);
for (const name of CRYPTO_PYPI) {
  const key2 = canonicalPypi(name);
  if (!pypiDownloads.has(key2)) pypiDownloads.set(key2, 1e6);
}
var pypiNames = [...pypiDownloads.keys()];
var npmRank = new Map(npmNames.map((n, i) => [n, i]));
function isPopular(name, eco) {
  return eco === "npm" ? npmRank.has(name) : pypiDownloads.has(canonicalPypi(name));
}
function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const rows = a.length + 1;
  const cols = b.length + 1;
  let prevPrev = [];
  let prev = Array.from({ length: cols }, (_, j) => j);
  for (let i = 1; i < rows; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, prevPrev[j - 2] + 1);
      }
      cur.push(v);
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prevPrev = prev;
    prev = cur;
  }
  return prev[cols - 1];
}
var HOMOGLYPHS = [
  [/rn/g, "m"],
  [/vv/g, "w"],
  [/0/g, "o"],
  [/1/g, "l"]
];
function squash(name) {
  return name.toLowerCase().replace(/^@/, "").replace(/[-_./]+/g, "");
}
function deglyph(name) {
  let s = squash(name);
  for (const [re, to] of HOMOGLYPHS) s = s.replace(re, to);
  return s;
}
var squashIndex = /* @__PURE__ */ new Map();
var glyphIndex = /* @__PURE__ */ new Map();
function indexFor(eco) {
  if (!squashIndex.has(eco)) {
    const names = eco === "npm" ? npmNames : pypiNames;
    const sq = /* @__PURE__ */ new Map();
    const gl = /* @__PURE__ */ new Map();
    for (const n of names) {
      if (!sq.has(squash(n))) sq.set(squash(n), n);
      if (!gl.has(deglyph(n))) gl.set(deglyph(n), n);
    }
    squashIndex.set(eco, sq);
    glyphIndex.set(eco, gl);
  }
  return { sq: squashIndex.get(eco), gl: glyphIndex.get(eco) };
}
var AFFIXES = [/^python-?/, /^py-?/, /-?py$/, /-?python3?$/, /^node-?/, /-?js$/, /-?sdk$/, /-?api$/, /-?lib$/, /-?official$/, /-?v\d$/, /\d$/];
var CRYPTO_TARGETS = new Set([...CRYPTO_NPM, ...CRYPTO_PYPI].map((n) => squash(n)));
function findTyposquat(name, eco) {
  if (isPopular(name, eco)) return null;
  const key2 = eco === "pypi" ? canonicalPypi(name) : name.toLowerCase();
  const { sq, gl } = indexFor(eco);
  const squashed = squash(key2);
  const sameLetters = sq.get(squashed);
  if (sameLetters && sameLetters !== name && eco === "npm") {
    return { target: sameLetters, kind: sameLetters.startsWith("@") || key2.startsWith("@") ? "scope" : "separator", distance: 0 };
  }
  const glyph = gl.get(deglyph(key2));
  if (glyph && squash(glyph) !== squashed) return { target: glyph, kind: "homoglyph", distance: 1 };
  if (squashed.length >= 5) {
    const names = eco === "npm" ? npmNames : pypiNames;
    let best = null;
    for (const cand of names) {
      const target = eco === "pypi" ? cand : cand.toLowerCase();
      if (target === key2) continue;
      const len = target.length;
      if (Math.abs(len - key2.length) > 2) continue;
      const allowed = len >= 9 ? 2 : len >= 5 ? 1 : 0;
      if (allowed === 0) continue;
      const d = editDistance(key2, target, allowed);
      if (d <= allowed && (!best || d < best.distance)) {
        best = { target: cand, kind: "lookalike", distance: d };
        if (d === 1) break;
      }
    }
    if (best) return best;
  }
  for (const re of AFFIXES) {
    const stripped = squashed.replace(re, "");
    if (stripped !== squashed && stripped.length >= 3 && CRYPTO_TARGETS.has(stripped)) {
      const target = [...CRYPTO_NPM, ...CRYPTO_PYPI].find((n) => squash(n) === stripped);
      return { target, kind: "affix", distance: 0 };
    }
  }
  return null;
}

// packages/core/src/registry/pypi.ts
async function getPypiProject(name, timeoutMs = 1e4) {
  return fetchJson(`https://pypi.org/pypi/${encodeURIComponent(canonicalPypi(name))}/json`, {
    timeoutMs,
    maxBytes: 30 * 1024 * 1024
  });
}
function resolvePypiSpec(p, spec) {
  const live = Object.entries(p.releases).filter(([, files]) => files.length > 0 && !files.every((f) => f.yanked)).map(([v]) => v);
  if (!spec) return live.includes(p.info.version) ? p.info.version : maxSatisfyingPep440(live);
  return maxSatisfyingPep440(live, spec);
}
function pypiCreated(p) {
  let first;
  for (const files of Object.values(p.releases)) {
    for (const f of files) {
      const t = f.upload_time_iso_8601 ? Date.parse(f.upload_time_iso_8601) : NaN;
      if (!Number.isNaN(t) && (first === void 0 || t < first)) first = t;
    }
  }
  return first === void 0 ? void 0 : new Date(first);
}
function pypiRepoUrl(info) {
  const urls = Object.values(info.project_urls ?? {});
  return [...urls, info.home_page ?? ""].find((u) => /github\.com|gitlab\.com/i.test(u));
}

// packages/core/src/intel/osv.ts
var OSV = "https://api.osv.dev/v1";
function osvEcosystem(eco) {
  return eco === "npm" ? "npm" : "PyPI";
}
function advisoryUrl(id) {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}
function toAdvisory(v) {
  const text = `${v.summary ?? ""}`.toLowerCase();
  return {
    id: v.id,
    malicious: v.id.startsWith("MAL-") || /\b(malware|malicious code)\b/.test(text),
    summary: v.summary,
    url: advisoryUrl(v.id)
  };
}
function queryBody(q) {
  return {
    package: { name: q.name, ecosystem: osvEcosystem(q.ecosystem) },
    ...q.version ? { version: q.version } : {}
  };
}
async function osvQuery(q, timeoutMs = 8e3) {
  const res = await fetchJson(`${OSV}/query`, {
    method: "POST",
    body: JSON.stringify(queryBody(q)),
    timeoutMs
  });
  return (res?.vulns ?? []).map(toAdvisory);
}
var affectedCache = /* @__PURE__ */ new Map();
function getOsvAffected(id, name) {
  const key2 = `${id}|${name}`;
  let p = affectedCache.get(key2);
  if (!p) {
    p = fetchJson(`${OSV}/vulns/${encodeURIComponent(id)}`, { timeoutMs: 8e3 }).then((v) => {
      if (!v) return null;
      const entries = (v.affected ?? []).filter((a) => !a.package?.name || a.package.name.toLowerCase() === name.toLowerCase());
      const versions = entries.flatMap((a) => a.versions ?? []);
      const allVersions = entries.some(
        (a) => (a.ranges ?? []).some(
          (r) => r.events.some((e) => e.introduced === "0") && !r.events.some((e) => e.fixed || e.last_affected)
        )
      );
      return { allVersions, versions, summary: v.summary };
    }).catch(() => null);
    affectedCache.set(key2, p);
  }
  return p;
}
async function osvQueryBatch(queries, timeoutMs = 1e4) {
  const out = [];
  for (let i = 0; i < queries.length; i += 1e3) {
    const chunk = queries.slice(i, i + 1e3);
    const res = await fetchJson(`${OSV}/querybatch`, {
      method: "POST",
      body: JSON.stringify({ queries: chunk.map(queryBody) }),
      timeoutMs
    });
    for (let j = 0; j < chunk.length; j++) {
      out.push((res?.results[j]?.vulns ?? []).map((v) => toAdvisory({ id: v.id })));
    }
  }
  return out;
}

// packages/core/src/intel/deps.ts
function key(d) {
  const name = d.ecosystem === "pypi" ? canonicalPypi(d.name) : d.name;
  return `${d.ecosystem}:${name}@${d.version ?? d.spec ?? ""}`;
}
function rangeAllows(eco, spec, version) {
  if (!spec || spec === "*" || spec === "latest") return false;
  if (eco === "npm") {
    try {
      return import_semver2.default.satisfies(version, spec, { includePrerelease: false });
    } catch {
      return false;
    }
  }
  return satisfiesPep440(version, spec);
}
async function publishedSubset(eco, name, versions) {
  try {
    if (eco === "npm") {
      const list = await getNpmVersionList(name);
      return list ? versions.filter((v) => list.includes(v)) : versions;
    }
    const project = await getPypiProject(name);
    if (!project) return versions;
    return versions.filter((v) => (project.releases[v] ?? []).some((f) => !f.yanked));
  } catch {
    return versions;
  }
}
async function checkDependencies(deps, opts) {
  const unique = /* @__PURE__ */ new Map();
  for (const d of deps) if (!unique.has(key(d))) unique.set(key(d), d);
  const list = [...unique.values()].slice(0, 4e3);
  if (unique.size > list.length) opts.notes.push(`Checked the first ${list.length} of ${unique.size} dependencies against OSV.`);
  const findings = [];
  let osv = [];
  try {
    osv = await osvQueryBatch(list.map((d) => ({ ecosystem: d.ecosystem, name: d.ecosystem === "pypi" ? canonicalPypi(d.name) : d.name, version: d.version })));
  } catch (err) {
    opts.notes.push(`OSV malware lookup failed: ${err.message}`);
  }
  await Promise.all(
    list.map(async (dep, i) => {
      const mal = (osv[i] ?? []).filter((a) => a.malicious);
      if (!mal.length) return;
      const label = `${dep.name}${dep.version ? `@${dep.version}` : dep.spec ? ` (${dep.spec})` : ""}`;
      const evidence = [{ file: dep.source, snippet: label, url: mal[0].url }];
      if (dep.version) {
        findings.push({
          id: `dep.malicious:${dep.ecosystem}:${dep.name}`,
          severity: "critical",
          category: "intel",
          title: `Depends on known malware: ${label}`,
          detail: `${mal.map((m) => m.id).join(", ")}: this exact version is listed as malicious in the OSV / OpenSSF malicious-packages database.`,
          advice: "Remove it. If it was ever installed on a machine, rotate every key and secret that machine could reach.",
          evidence
        });
        return;
      }
      const affected = await Promise.all(mal.map((m) => getOsvAffected(m.id, dep.name)));
      if (affected.some((a) => a?.allVersions)) {
        findings.push({
          id: `dep.malicious:${dep.ecosystem}:${dep.name}`,
          severity: "critical",
          category: "intel",
          title: `Depends on a known malicious package: ${dep.name}`,
          detail: `${mal.map((m) => m.id).join(", ")}: every version of this package is listed as malware.`,
          advice: "Remove it. If it was ever installed, treat that machine's keys and secrets as stolen.",
          evidence
        });
        return;
      }
      const bad = [...new Set(affected.flatMap((a) => a?.versions ?? []))];
      const allowed = bad.filter((v) => rangeAllows(dep.ecosystem, dep.spec, v));
      const stillPublished = allowed.length ? await publishedSubset(dep.ecosystem, dep.name, allowed) : [];
      findings.push(
        allowed.length ? {
          id: `dep.hijacked-range:${dep.ecosystem}:${dep.name}`,
          severity: stillPublished.length ? "high" : "low",
          category: "intel",
          title: stillPublished.length ? `Version range for ${dep.name} can install a hijacked release (${stillPublished.join(", ")})` : `Version range for ${dep.name} covers a hijacked release that has since been removed (${allowed.join(", ")})`,
          detail: stillPublished.length ? `${mal.map((m) => m.id).join(", ")}: those releases were published by attackers and are still downloadable. "${dep.spec}" can resolve to one.` : `${mal.map((m) => m.id).join(", ")}: fresh installs can't get it any more, but check that no lockfile pins it.`,
          advice: "Pin to a known-good version and check your lockfile.",
          evidence
        } : {
          id: `dep.hijacked-history:${dep.ecosystem}:${dep.name}`,
          severity: "info",
          category: "intel",
          title: `${dep.name} once had hijacked releases (${bad.join(", ") || "see advisory"})`,
          detail: "Your declared range excludes them, so this is informational.",
          evidence
        }
      );
    })
  );
  const direct = list.filter((d) => d.direct);
  await Promise.all(
    direct.map(async (dep) => {
      const squat = findTyposquat(dep.name, dep.ecosystem);
      if (squat) {
        if (!opts.skipDownloads) {
          if (dep.ecosystem === "npm") {
            const weekly = await getNpmWeeklyDownloads(dep.name);
            if (weekly !== null && weekly >= 1e3) return;
          } else {
            const project = await getPypiProject(dep.name).catch(() => null);
            if (!project) return;
            const first = pypiCreated(project);
            if (first && Date.now() - first.getTime() > 2 * 365 * 864e5) return;
          }
        }
        findings.push({
          id: `dep.typosquat:${dep.ecosystem}:${dep.name}`,
          severity: "high",
          category: "typosquat",
          title: `"${dep.name}" looks like a typosquat of "${squat.target}"`,
          detail: `It differs from the popular package "${squat.target}" only by ${squat.kind === "lookalike" ? `${squat.distance} character${squat.distance === 1 ? "" : "s"}` : squat.kind === "scope" ? "its npm scope" : squat.kind === "separator" ? "punctuation" : squat.kind === "affix" ? "a prefix/suffix" : "look-alike characters"}. Attackers register these names to catch typos and AI-hallucinated imports.`,
          advice: `Use "${squat.target}" unless you're sure this is the package you meant.`,
          evidence: [{ file: dep.source, snippet: `${dep.name}${dep.spec ? ` ${dep.spec}` : ""}` }]
        });
      }
      const brands = matchBrands(dep.name).filter((b) => !(dep.ecosystem === "npm" && b.npmScopes.some((s) => dep.name.toLowerCase().startsWith(`${s}/`))));
      if (brands.length && !isPopular(dep.name, dep.ecosystem)) {
        findings.push({
          id: `dep.brand:${dep.ecosystem}:${dep.name}`,
          severity: "low",
          category: "typosquat",
          title: `"${dep.name}" uses the ${brands[0].label} name but isn't an official package`,
          detail: `Fake "${brands[0].label}" packages are a favourite way to target bot builders. Check who publishes it before trusting it with keys.`,
          evidence: [{ file: dep.source, snippet: dep.name }]
        });
      }
    })
  );
  return findings;
}

// packages/core/src/verdict.ts
var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
function severityRank(s) {
  return SEVERITY_ORDER.indexOf(s);
}
function sortFindings(findings) {
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

// packages/core/src/install/check.ts
var INSTALL_HOOK_DANGER = /\bcurl\b|\bwget\b|powershell|Invoke-WebRequest|\biwr\b|node\s+-e\b|python[0-9.]*\s+-c\b|base64|\beval\b|https?:\/\//i;
var CACHE_TTL = { allow: 12 * 36e5, ask: 24 * 36e5, deny: 7 * 24 * 36e5 };
function loadCache(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return {};
  }
}
function saveCache(path, cache) {
  try {
    mkdirSync(dirname(path), { recursive: true });
    const now = Date.now();
    const kept = Object.entries(cache).filter(([, e]) => now - e.at < CACHE_TTL.deny).slice(-2e3);
    writeFileSync(path, JSON.stringify(Object.fromEntries(kept)));
  } catch {
  }
}
function decide(findings, strict = true) {
  const worst = sortFindings(findings)[0]?.severity;
  if (!worst) return "allow";
  if (worst === "critical") return "deny";
  if (worst === "high") return strict ? "deny" : "ask";
  if (worst === "medium") return "ask";
  return "allow";
}
function mergeDecision(a, b) {
  const rank = { deny: 0, ask: 1, allow: 2 };
  return rank[a] <= rank[b] ? a : b;
}
function squatF(name, target, severity, detail) {
  return { id: "pkg.typosquat", severity, category: "typosquat", title: `"${name}" looks like a typosquat of "${target}"`, detail, advice: `did you mean "${target}"?` };
}
async function checkNpmPackage(name, spec, executes) {
  const label = `${name}${spec ? `@${spec}` : ""} (npm${executes ? ", runs immediately" : ""})`;
  const findings = [];
  const popular = isPopular(name, "npm");
  let created;
  let doc = null;
  if (popular && isDirectSpec(spec)) doc = await getNpmVersion(name, spec || "latest");
  else {
    const p = await getNpmPackument(name);
    if (p) {
      const v = resolveNpmSpec(p, spec);
      doc = v ? p.versions[v] ?? null : null;
      created = p.time?.created;
    }
  }
  if (!doc) {
    const squat = findTyposquat(name, "npm");
    if (squat) findings.push(squatF(name, squat.target, "medium", "npm has no such package right now, so this install fails, but the name is a near-miss of a popular package. Don't retry with a similar-looking name."));
    return { label, decision: decide(findings), findings };
  }
  const resolved = `${name}@${doc.version} (npm${executes ? ", runs immediately" : ""})`;
  const [advisories, weekly] = await Promise.all([osvQuery({ ecosystem: "npm", name, version: doc.version }).catch(() => []), getNpmWeeklyDownloads(name)]);
  const mal = advisories.filter((a) => a.malicious);
  if (mal.length) {
    findings.push({
      id: "intel.osv-malicious",
      severity: "critical",
      category: "intel",
      title: `known malware (${mal.map((m) => m.id).join(", ")})`,
      detail: mal[0].summary ?? "Listed in the OSV / OpenSSF malicious-packages database.",
      evidence: mal.map((m) => ({ url: m.url }))
    });
  }
  if (doc.version.endsWith("-security")) {
    findings.push({ id: "intel.npm-security-placeholder", severity: "critical", category: "intel", title: "taken down by npm for being malicious", detail: "Only a 0.0.1-security placeholder remains." });
  }
  if (!popular) {
    const squat = findTyposquat(name, "npm");
    if (squat && (weekly === null || weekly < 5e3)) {
      findings.push(squatF(name, squat.target, weekly === null || weekly < 1e3 ? "high" : "medium", `${weekly ?? "unknown"} weekly downloads, versus one of npm's most-used packages.`));
    }
    const ageDays = daysSince(created);
    for (const brand of matchBrands(name)) {
      const emails = [doc._npmUser?.email, ...(doc.maintainers ?? []).map((m) => m.email)].filter((e) => Boolean(e));
      if (isOfficialPublisher(brand, { scope: npmScope(name), emails })) continue;
      const claims = isOfficialPublisher(brand, { repositoryUrl: repoUrlOf(doc.repository), homepage: doc.homepage });
      const fresh = ageDays !== void 0 && ageDays < 120 || weekly !== null && weekly < 500;
      findings.push({
        id: "pkg.brand",
        severity: claims || fresh ? "high" : "medium",
        category: "typosquat",
        title: `uses the ${brand.label} name but isn't published by ${brand.label}`,
        detail: `${ageDays !== void 0 ? `First published ${ageDays} days ago, ` : ""}${weekly ?? "unknown"} downloads last week.`,
        advice: brand.npmScopes[0] ? `official packages live under ${brand.npmScopes[0]}/` : void 0
      });
      break;
    }
    if (ageDays !== void 0 && ageDays < 7) {
      findings.push({ id: "pkg.new", severity: "medium", category: "metadata", title: `first published ${ageDays} day(s) ago`, detail: "Brand-new packages are where most npm malware lives." });
    }
    const hooks = Object.entries(doc.scripts ?? {}).filter(([k]) => k === "preinstall" || k === "install" || k === "postinstall");
    for (const [hook, script] of hooks) {
      if (INSTALL_HOOK_DANGER.test(script)) {
        findings.push({ id: "pkg.install-hook-danger", severity: "high", category: "install-script", title: `runs a risky "${hook}" script: ${script.slice(0, 80)}`, detail: "It runs automatically during install." });
      } else if ((weekly ?? 0) < 1e3) {
        findings.push({ id: "pkg.install-hook", severity: "low", category: "install-script", title: `runs a "${hook}" script on install`, detail: script.slice(0, 120) });
      }
    }
  }
  return { label: resolved, decision: decide(findings), findings };
}
async function checkPypiPackage(name, spec, executes) {
  const label = `${name}${spec ?? ""} (PyPI${executes ? ", runs immediately" : ""})`;
  const findings = [];
  const project = await getPypiProject(name);
  if (!project) {
    const squat = findTyposquat(name, "pypi");
    if (squat) findings.push(squatF(name, squat.target, "medium", "PyPI has no such project right now, so this install fails, but the name is a near-miss of a popular one."));
    return { label, decision: decide(findings), findings };
  }
  const version = resolvePypiSpec(project, spec);
  const resolved = `${project.info.name}==${version ?? "?"} (PyPI${executes ? ", runs immediately" : ""})`;
  if (version) {
    const advisories = await osvQuery({ ecosystem: "pypi", name: canonicalPypi(name), version }).catch(() => []);
    const mal = advisories.filter((a) => a.malicious);
    if (mal.length) {
      findings.push({ id: "intel.osv-malicious", severity: "critical", category: "intel", title: `known malware (${mal.map((m) => m.id).join(", ")})`, detail: mal[0].summary ?? "Listed in the OSV / OpenSSF malicious-packages database.", evidence: mal.map((m) => ({ url: m.url })) });
    }
  }
  if (!isPopular(name, "pypi")) {
    const ageDays = daysSince(pypiCreated(project));
    const squat = findTyposquat(name, "pypi");
    if (squat) findings.push(squatF(name, squat.target, ageDays !== void 0 && ageDays < 365 ? "high" : "medium", `"${squat.target}" is one of PyPI's most downloaded projects; this one is not.`));
    const emails = `${project.info.author_email ?? ""},${project.info.maintainer_email ?? ""}`.match(/[\w.+-]+@[\w.-]+/g) ?? [];
    for (const brand of matchBrands(name)) {
      const official = isOfficialPublisher(brand, { repositoryUrl: pypiRepoUrl(project.info), homepage: project.info.home_page, emails }) && (ageDays ?? 0) > 60;
      if (official) continue;
      findings.push({
        id: "pkg.brand",
        severity: ageDays !== void 0 && ageDays < 120 ? "high" : "medium",
        category: "typosquat",
        title: `uses the ${brand.label} name but isn't published by ${brand.label}`,
        detail: ageDays !== void 0 ? `First uploaded ${ageDays} days ago.` : "Check who publishes it."
      });
      break;
    }
    if (ageDays !== void 0 && ageDays < 7) {
      findings.push({ id: "pkg.new", severity: "medium", category: "metadata", title: `first uploaded ${ageDays} day(s) ago`, detail: "Brand-new packages are where most PyPI malware lives." });
    }
  }
  return { label: resolved, decision: decide(findings), findings };
}
function readLocal(cwd, file) {
  const path = isAbsolute(file) ? file : join(cwd, file);
  if (!existsSync(path)) return null;
  try {
    const text = readFileSync(path, "utf8");
    return { path: file.replace(/\\/g, "/"), text, size: text.length };
  } catch {
    return null;
  }
}
async function checkManifest(intent, cwd, notes) {
  const names = intent.ecosystem === "npm" ? ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"] : intent.file ? [intent.file] : ["requirements.txt", "pyproject.toml", "poetry.lock"];
  const files = names.map((n) => readLocal(cwd, n)).filter((f) => f !== null);
  const label = intent.ecosystem === "npm" ? "the project's npm dependencies" : `requirements in ${intent.file ?? "the project"}`;
  if (!files.length) return { label, decision: "allow", findings: [] };
  const manifest = analyzeManifests(files);
  const findings = await checkDependencies(manifest.dependencies, { notes, skipDownloads: true });
  findings.push(...manifest.findings.filter((f) => f.id === "manifest.install-script-download" || f.id === "manifest.custom-index"));
  return { label, decision: decide(findings, false), findings };
}
async function checkRepo(intent, notes) {
  const ref = { owner: intent.owner, repo: intent.repo, ref: intent.ref };
  const label = `github.com/${intent.owner}/${intent.repo}`;
  const findings = [];
  const repo = await getGithubRepo(ref).catch(() => null);
  if (repo) {
    const owner = await getGithubOwner(repo.owner.login).catch(() => null);
    findings.push(...repoSignals({ repo, owner }));
  }
  const [readme, pkg, reqs] = await Promise.all([fetchGithubRaw(ref, "README.md"), fetchGithubRaw(ref, "package.json"), fetchGithubRaw(ref, "requirements.txt")]);
  if (readme) findings.push(...scanScamText([{ path: "README.md", text: readme, size: readme.length }]));
  const manifestFiles = [];
  if (pkg) manifestFiles.push({ path: "package.json", text: pkg, size: pkg.length });
  if (reqs) manifestFiles.push({ path: "requirements.txt", text: reqs, size: reqs.length });
  if (manifestFiles.length) {
    const manifest = analyzeManifests(manifestFiles);
    findings.push(...manifest.findings.filter((f) => severityRank(f.severity) <= severityRank("medium")));
    findings.push(...await checkDependencies(manifest.dependencies, { notes, skipDownloads: true }));
  }
  return { label, decision: decide(findings, false), findings };
}
async function checkIntent(intent, cwd, notes) {
  switch (intent.kind) {
    case "package":
      return intent.ecosystem === "npm" ? checkNpmPackage(intent.name, intent.spec, intent.executes) : checkPypiPackage(intent.name, intent.spec, intent.executes);
    case "manifest":
      return checkManifest(intent, cwd, notes);
    case "repo":
      return checkRepo(intent, notes);
    case "remote-archive":
      return {
        label: intent.url,
        decision: "ask",
        findings: [{ id: "install.remote-archive", severity: "medium", category: "install-script", title: "installs code straight from a URL", detail: "It bypasses the package registry, so it can't be checked against malware intel." }]
      };
    case "pipe-to-shell":
      if (intent.url && TRUSTED_INSTALL_HOSTS.test(intent.url)) return { label: intent.url, decision: "allow", findings: [] };
      return {
        label: intent.url ?? "remote script",
        decision: "ask",
        findings: [{ id: "install.pipe-to-shell", severity: "medium", category: "execution", title: "pipes a downloaded script straight into a shell", detail: "It runs with your permissions without being reviewed." }]
      };
    case "custom-registry":
      return {
        label: intent.registry,
        decision: "ask",
        findings: [{ id: "install.custom-registry", severity: "medium", category: "install-script", title: "uses a non-default package registry", detail: "Unknown registries can serve anything under familiar names." }]
      };
  }
}
function cacheKey(i) {
  return i.kind === "package" ? `${i.ecosystem}:${i.ecosystem === "pypi" ? canonicalPypi(i.name) : i.name}@${i.spec ?? ""}:${i.executes ? "x" : ""}` : void 0;
}
function allowName(i) {
  if (i.kind === "package") return i.name.toLowerCase();
  if (i.kind === "repo") return `${i.owner}/${i.repo}`.toLowerCase();
  return void 0;
}
async function checkInstallCommand(command, opts = {}) {
  const intents = parseInstallCommand(command);
  const notes = [];
  if (!intents.length) return { decision: "allow", reason: "", verdicts: [], notes };
  const allow = new Set((opts.allow ?? []).map((a) => a.toLowerCase()));
  const cachePath = opts.cachePath === false ? void 0 : opts.cachePath ?? join(homedir(), ".botguard", "hook-cache.json");
  const cache = cachePath ? loadCache(cachePath) : {};
  const cwd = opts.cwd ?? process.cwd();
  const verdicts = await Promise.all(
    intents.slice(0, 20).map(async (intent) => {
      const name = allowName(intent);
      if (name && allow.has(name)) return { label: name, decision: "allow", findings: [] };
      const key2 = cacheKey(intent);
      const hit = key2 ? cache[key2] : void 0;
      if (hit && Date.now() - hit.at < CACHE_TTL[hit.verdict.decision]) return hit.verdict;
      try {
        const v = await checkIntent(intent, cwd, notes);
        if (key2) cache[key2] = { at: Date.now(), verdict: v };
        return v;
      } catch (err) {
        notes.push(`Couldn't check ${name ?? intent.kind}: ${err.message}`);
        return { label: name ?? intent.kind, decision: "allow", findings: [] };
      }
    })
  );
  if (cachePath) saveCache(cachePath, cache);
  const decision = verdicts.reduce((d, v) => mergeDecision(d, v.decision), "allow");
  return { decision, reason: formatReason(decision, verdicts), verdicts, notes };
}
function formatReason(decision, verdicts) {
  if (decision === "allow") return "";
  const flagged = verdicts.filter((v) => v.decision !== "allow");
  const lines = flagged.flatMap((v) => {
    const top = sortFindings(v.findings).filter((f) => f.severity !== "info" && f.severity !== "low").slice(0, 3);
    return [`- ${v.label}: ${top.map((f) => f.title + (f.advice ? ` (${f.advice})` : "")).join("; ")}`];
  });
  if (decision === "deny") {
    return [
      "BotGuard blocked this install: it matches known malware or a strong typosquat/impersonation signal.",
      ...lines,
      "Do not retry with a similar-looking name. Use the official package, or ask the user which exact package they want (they can allow it with BOTGUARD_ALLOW=<name>)."
    ].join("\n");
  }
  return ["BotGuard flagged this for a second look:", ...lines, "Approve only if you recognise the package and its publisher."].join("\n");
}

// packages/cli/src/hook.ts
function allowList(cwd) {
  const fromEnv = (process.env.BOTGUARD_ALLOW ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const file = join2(cwd, ".botguard.json");
  if (!existsSync2(file)) return fromEnv;
  try {
    const cfg = JSON.parse(readFileSync2(file, "utf8"));
    return [...fromEnv, ...cfg.allow ?? []];
  } catch {
    return fromEnv;
  }
}
function withTimeout(p, ms) {
  return Promise.race([p, new Promise((r) => setTimeout(() => r("timeout"), ms).unref())]);
}
function decisionJson(result) {
  const decision = result.decision === "deny" ? "deny" : "ask";
  const flagged = result.verdicts.filter((v) => v.decision !== "allow").map((v) => v.label);
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: result.reason
    },
    systemMessage: `BotGuard ${decision === "deny" ? "blocked" : "flagged"}: ${flagged.join(", ")}`
  });
}
async function runClaudeCodeHook(raw) {
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    return { exitCode: 0 };
  }
  if (!input.tool_name || !GUARDED_TOOLS.has(input.tool_name)) return { exitCode: 0 };
  const command = typeof input.tool_input?.command === "string" ? input.tool_input.command : "";
  if (!command || !MAYBE_INSTALL.test(command)) return { exitCode: 0 };
  const cwd = input.cwd ?? process.cwd();
  const failClosed = process.env.BOTGUARD_FAIL_CLOSED === "1";
  try {
    const result = await withTimeout(checkInstallCommand(command, { cwd, allow: allowList(cwd) }), Number(process.env.BOTGUARD_TIMEOUT_MS ?? 2e4));
    if (result === "timeout") {
      if (failClosed) {
        return {
          exitCode: 0,
          stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: "BotGuard couldn't finish checking this install in time." } })
        };
      }
      return { exitCode: 0, stdout: JSON.stringify({ systemMessage: "BotGuard: install check timed out, so this install was not verified." }) };
    }
    if (result.decision === "allow") return { exitCode: 0 };
    return { exitCode: 0, stdout: decisionJson(result) };
  } catch (err) {
    if (failClosed) {
      return {
        exitCode: 0,
        stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: `BotGuard check failed: ${err.message}` } })
      };
    }
    return { exitCode: 0 };
  }
}
export {
  runClaudeCodeHook
};
