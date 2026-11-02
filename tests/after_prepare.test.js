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

test('electron: worker scripts and what they import stay plain and are excluded in the loader', function(t) {
    var project = electronProject(t);
    write(project.www, 'js/proxy.js', 'var w = new Worker(\'./js/w/worker.js\'); new Worker(dynamicName);');
    write(project.www, 'js/w/worker.js', 'self.importScripts(\n  \'../../lib/dep.js\',\n  "sibling.js"\n);');
    write(project.www, 'js/w/sibling.js', 'importScripts("nested.js");');
    write(project.www, 'js/w/nested.js', 'var nested;');
    write(project.www, 'lib/dep.js', 'var dep;');
    write(project.www, 'lib/other.js', 'var other;');
    runHook(HOOK, fakeContext(project.root, 'electron', 'www'));

    ['js/w/worker.js', 'js/w/sibling.js', 'js/w/nested.js', 'lib/dep.js'].forEach(function(rel) {
        assert.ok(fs.readFileSync(path.join(project.www, rel), 'utf8').indexOf(';') > -1, rel + ' stays plain');
    });
    var slots = readLoaderSlots(path.join(project.www, 'cdv-electron-crypt.js'));
    assert.strictEqual(decrypt(path.join(project.www, 'lib/other.js'), slots).toString(), 'var other;');
    assert.strictEqual(decrypt(path.join(project.www, 'js/proxy.js'), slots).toString().indexOf('var w'), 0);

    var loader = fs.readFileSync(path.join(project.www, 'cdv-electron-crypt.js'), 'utf8');
    var excludes = JSON.parse(loader.match(/EXCLUDE_FILES = (\[.*\]);/)[1]);
    ['/js/w/worker.js', '/lib/dep.js', '/js/w/nested.js'].forEach(function(rel) {
        assert.ok(excludes.some(function(pattern) { return new RegExp(pattern).test(rel); }), rel + ' is excluded');
    });
    assert.ok(!excludes.some(function(pattern) { return new RegExp(pattern).test('/lib/other.js'); }));
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

function logsOfHook(context) {
    var lines = [];
    var streams = ['log', 'info', 'warn', 'error', 'debug'];
    var saved = streams.map(function(name) { return console[name]; });
    var stdout = process.stdout.write;
    var capture = function() { lines.push(Array.prototype.join.call(arguments, ' ')); return true; };
    streams.forEach(function(name) { console[name] = capture; });
    process.stdout.write = capture;
    try {
        delete require.cache[HOOK];
        withFixedRandom(function() { require(HOOK)(context); });
    } finally {
        process.stdout.write = stdout;
        streams.forEach(function(name, i) { console[name] = saved[i]; });
    }
    return lines.join('\n');
}

function assertNoSecret(output) {
    var key = Buffer.alloc(24, 7).toString('base64');
    var iv = Buffer.alloc(12, 7).toString('base64');
    assert.ok(output.indexOf('encrypt: ') > -1, 'the hook ran and logged its work');
    assert.ok(output.indexOf(key) === -1, 'the key is not in the build log');
    assert.ok(output.indexOf(iv) === -1, 'the iv is not in the build log');
}

test('electron: the build log has no key or iv', function(t) {
    var project = electronProject(t);
    assertNoSecret(logsOfHook(fakeContext(project.root, 'electron', 'www')));
});

test('android: the build log has no key or iv', function(t) {
    var project = androidProject(t);
    assertNoSecret(logsOfHook(fakeContext(project.root, 'android', 'app/src/main/assets/www')));
});

test('ios: the build log has no key or iv', function(t) {
    var root = tempDir(t);
    write(root, 'platforms/ios/www/index.html', '<html>x</html>');
    write(root, 'platforms/ios/www/js/app.js', 'var a = 1;');
    write(root, 'platforms/ios/App/config.xml', '');
    write(root, 'platforms/ios/App.xcodeproj/project.pbxproj', '');
    write(root, 'platforms/ios/App/Plugins/cordova-plugin-crypt-file/CDVCryptURLProtocol.m',
        'kCryptKey = @"";\nkCryptIv = @"";\nkIncludeFiles[] = {};\nkExcludeFiles[] = {};\nkIncludeFileLength = 0;\nkExcludeFileLength = 0;\n');
    var output = logsOfHook(fakeContext(root, 'ios', 'www'));
    assertNoSecret(output);
    var source = fs.readFileSync(path.join(root, 'platforms/ios/App/Plugins/cordova-plugin-crypt-file/CDVCryptURLProtocol.m'), 'utf8');
    assert.ok(source.indexOf(Buffer.alloc(24, 7).toString('base64')) > -1, 'the key still reaches the build');
});
