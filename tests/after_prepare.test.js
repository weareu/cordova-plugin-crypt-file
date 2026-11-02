'use strict';

// Runs the real hook against fake platform trees: `node --test tests/after_prepare.test.js`.
var assert = require('node:assert');
var childProcess = require('node:child_process');
var crypto = require('node:crypto');
var fs = require('node:fs');
var Module = require('node:module');
var os = require('node:os');
var path = require('node:path');
var test = require('node:test');

var PLUGIN_DIR = path.join(__dirname, '..');
var HOOK = path.join(PLUGIN_DIR, 'hooks/after_prepare.js');
// The last commit before the electron platform: the Android reference.
var PRE_ELECTRON_COMMIT = 'b2d5d4c';
var JAVA_SRC = 'src/android/com/tkyaji/cordova/DecryptResource.java';

var realLoad = Module._load;
Module._load = function(request) {
    if (request === 'q') {
        return { defer: function Deferred() {
            return { resolve: function() {}, promise: Promise.resolve() };
        } };
    }
    return realLoad.apply(this, arguments);
};

function write(root, rel, content) {
    var file = path.join(root, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
}

function cryptFilesFromPluginXml() {
    var xml = fs.readFileSync(path.join(PLUGIN_DIR, 'plugin.xml'), 'utf8');
    var block = xml.match(/<include>([\s\S]*?)<\/include>/)[1];
    var regexes = [];
    block.replace(/regex="([^"]+)"/g, function(_, regex) {
        regexes.push({ tag: 'file', attrib: { regex: regex }, _children: [] });
    });
    return { findall: function() {
        return [{ _children: [{ tag: 'include', _children: regexes }, { tag: 'exclude', _children: [] }] }];
    } };
}

function fakeContext(projectRoot, platform, wwwRel) {
    var modules = {
        'cordova-lib/src/cordova/util': { cdProjectRoot: function() { return projectRoot; } },
        'cordova-lib/src/platforms/platforms': { getPlatformApi: function(_, platformPath) {
            return { getPlatformInfo: function() {
                return {
                    locations: { www: path.join(platformPath, wwwRel) },
                    projectConfig: { path: path.join(platformPath, 'config.xml') }
                };
            } };
        } },
        'cordova-common': {
            xmlHelpers: { parseElementtreeSync: cryptFilesFromPluginXml },
            ConfigParser: function ConfigParser(file) {
                var content = { tag: 'content', attrib: { src: 'index.html' } };
                this.doc = { getroot: function() { return { getchildren: function() { return [content]; } }; } };
                this.write = function() { fs.writeFileSync(file, content.attrib.src); };
            }
        }
    };
    return {
        requireCordovaModule: function(name) { return modules[name]; },
        opts: {
            platforms: [platform],
            plugin: {
                id: 'cordova-plugin-crypt-file',
                dir: PLUGIN_DIR,
                pluginInfo: { getPlatformsArray: function() { return ['ios', 'android', 'electron']; } }
            }
        }
    };
}

function quietly(fn) {
    var log = console.log;
    console.log = function() {};
    try {
        return fn();
    } finally {
        console.log = log;
    }
}

function runHook(hookFile, context) {
    delete require.cache[hookFile];
    return quietly(function() {
        return require(hookFile)(context);
    });
}

function tempDir(t) {
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-hook-'));
    t.after(function() { fs.rmSync(dir, { recursive: true, force: true }); });
    return dir;
}

function readLoaderSlots(file) {
    var src = fs.readFileSync(file, 'utf8');
    return {
        key: src.match(/CRYPT_KEY = '(.*)';/)[1],
        iv: src.match(/CRYPT_IV = '(.*)';/)[1]
    };
}

function decrypt(file, slots) {
    var decipher = crypto.createDecipheriv('aes-256-cbc', slots.key, slots.iv);
    return Buffer.concat([decipher.update(fs.readFileSync(file, 'utf8'), 'base64'), decipher.final()]);
}

function electronProject(t) {
    var root = tempDir(t);
    var www = 'platforms/electron/www';
    var loader = 'const CRYPT_KEY = \'\';\nconst CRYPT_IV = \'\';\nconst INCLUDE_FILES = [];\nconst EXCLUDE_FILES = [];\n';
    write(root, www + '/index.html', '<html>héllo</html>');
    write(root, www + '/templates/a.htm', '<b>a</b>');
    write(root, www + '/js/app.js', 'var app = "ünï";');
    write(root, www + '/js/latin1.js', Buffer.from([0x76, 0x61, 0x72, 0xe9]));
    write(root, www + '/css/a.css', 'a{}');
    write(root, www + '/img/logo.png', Buffer.from([0x89, 0x50]));
    write(root, www + '/package.json', '{}');
    write(root, www + '/cdv-electron-settings.json', '{}');
    write(root, www + '/cdv-electron-main.js', 'main');
    write(root, www + '/cdv-electron-preload.js', 'preload');
    write(root, www + '/cdv-electron-crypt.js', loader);
    write(root, www + '/node_modules/svc/index.js', 'service');
    return { root: root, www: path.join(root, www) };
}

test('electron: matching files round-trip, everything else stays plain', function(t) {
    var project = electronProject(t);
    runHook(HOOK, fakeContext(project.root, 'electron', 'www'));
    var slots = readLoaderSlots(path.join(project.www, 'cdv-electron-crypt.js'));

    assert.strictEqual(slots.key.length, 32);
    assert.strictEqual(slots.iv.length, 16);
    ['index.html', 'templates/a.htm', 'js/app.js', 'js/latin1.js', 'css/a.css'].forEach(function(rel) {
        assert.ok(fs.readFileSync(path.join(project.www, rel), 'utf8').match(/^[A-Za-z0-9+/]+=*$/), rel + ' is ciphertext');
    });
    assert.strictEqual(decrypt(path.join(project.www, 'index.html'), slots).toString(), '<html>héllo</html>');
    assert.strictEqual(decrypt(path.join(project.www, 'js/app.js'), slots).toString(), 'var app = "ünï";');
    assert.deepStrictEqual([...decrypt(path.join(project.www, 'js/latin1.js'), slots)], [0x76, 0x61, 0x72, 0xe9]);

    [['cdv-electron-main.js', 'main'], ['cdv-electron-preload.js', 'preload'], ['package.json', '{}'],
        ['cdv-electron-settings.json', '{}'], ['node_modules/svc/index.js', 'service']].forEach(function(pair) {
        assert.strictEqual(fs.readFileSync(path.join(project.www, pair[0]), 'utf8'), pair[1], pair[0] + ' stays plain');
    });
    assert.deepStrictEqual([...fs.readFileSync(path.join(project.www, 'img/logo.png'))], [0x89, 0x50]);
});

test('electron: every build gets a fresh key and iv', function(t) {
    var first = electronProject(t);
    var second = electronProject(t);
    runHook(HOOK, fakeContext(first.root, 'electron', 'www'));
    runHook(HOOK, fakeContext(second.root, 'electron', 'www'));
    var a = readLoaderSlots(path.join(first.www, 'cdv-electron-crypt.js'));
    var b = readLoaderSlots(path.join(second.www, 'cdv-electron-crypt.js'));
    assert.notStrictEqual(a.key, b.key);
    assert.notStrictEqual(a.iv, b.iv);
});

test('electron: a cordova-electron without the loader fails the build and leaves files plain', function(t) {
    var project = electronProject(t);
    fs.rmSync(path.join(project.www, 'cdv-electron-crypt.js'));
    assert.throws(function() {
        runHook(HOOK, fakeContext(project.root, 'electron', 'www'));
    }, /cdv-electron-crypt\.js is missing/);
    assert.strictEqual(fs.readFileSync(path.join(project.www, 'js/app.js'), 'utf8'), 'var app = "ünï";');
});

function androidProject(t) {
    var root = tempDir(t);
    var www = 'platforms/android/app/src/main/assets/www';
    write(root, www + '/index.html', '<html>x</html>');
    write(root, www + '/js/app.js', 'var a = 1;');
    write(root, www + '/img/logo.png', 'png');
    write(root, 'platforms/android/app/src/main/java/com/tkyaji/cordova/DecryptResource.java',
        fs.readFileSync(path.join(PLUGIN_DIR, JAVA_SRC)));
    write(root, 'platforms/android/config.xml', '');
    return { root: root, www: www };
}

function snapshot(root) {
    var out = {};
    (function walk(dir) {
        fs.readdirSync(dir, { withFileTypes: true }).forEach(function(entry) {
            var file = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(file);
            } else {
                out[path.relative(root, file)] = fs.readFileSync(file, 'base64');
            }
        });
    }(root));
    return out;
}

function withFixedRandom(fn) {
    var real = crypto.randomBytes;
    crypto.randomBytes = function(size) { return Buffer.alloc(size, 7); };
    try {
        return fn();
    } finally {
        crypto.randomBytes = real;
    }
}

test('android: output is byte-identical to the hook before the electron change', function(t) {
    var hookDir = tempDir(t);
    var oldHook = path.join(hookDir, 'after_prepare.js');
    fs.writeFileSync(oldHook, childProcess.execFileSync('git', ['show', PRE_ELECTRON_COMMIT + ':hooks/after_prepare.js'], { cwd: PLUGIN_DIR }));
    var before = androidProject(t);
    var after = androidProject(t);
    withFixedRandom(function() {
        runHook(oldHook, fakeContext(before.root, 'android', 'app/src/main/assets/www'));
        runHook(HOOK, fakeContext(after.root, 'android', 'app/src/main/assets/www'));
    });
    var snapshotBefore = snapshot(before.root);
    assert.notStrictEqual(snapshotBefore[before.www + '/js/app.js'], Buffer.from('var a = 1;').toString('base64'));
    assert.deepStrictEqual(snapshot(after.root), snapshotBefore);
});
