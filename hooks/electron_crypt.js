'use strict';

var fs = require('fs');
var path = require('path');

// The main process, its preload and plugin services are loaded by Node's own
// require, which never goes through the protocol handler, so they stay plain.
var ELECTRON_EXCLUDE = ['^/cdv-electron-[^/]*\\.js$', '^/node_modules/'];
var LOADER_FILE = 'cdv-electron-crypt.js';

function electronTargets(targets) {
    return { include: targets.include, exclude: ELECTRON_EXCLUDE.concat(targets.exclude) };
}

function isCryptPath(relPath, targets) {
    function matches(regexStr) {
        return new RegExp(regexStr).test(relPath);
    }
    return targets.include.some(matches) && !targets.exclude.some(matches);
}

function listRelativeFiles(wwwDir, relDir) {
    return fs.readdirSync(path.join(wwwDir, relDir), { withFileTypes: true }).reduce(function(files, entry) {
        var relPath = relDir + '/' + entry.name;
        if (relPath === '/node_modules' || entry.isSymbolicLink()) {
            return files;
        }
        return files.concat(entry.isDirectory() ? listRelativeFiles(wwwDir, relPath) : [relPath]);
    }, []);
}

function escapeRegExp(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stringLiterals(args) {
    return (args.match(/'[^']+'|"[^"]+"/g) || []).map(function(literal) {
        return literal.slice(1, -1);
    });
}

function allMatches(pattern, source) {
    var matches = [];
    var match = pattern.exec(source);
    while (match) {
        matches.push(match);
        match = pattern.exec(source);
    }
    return matches;
}

// Electron's file handler never sees a worker's own script or its importScripts,
// so Chromium reads them straight from disk: they can only run in plaintext.
function findWorkerScripts(wwwDir, relPaths) {
    var known = new Set(relPaths);
    var found = new Set();
    var queue = [];

    function enqueue(relPath) {
        if (known.has(relPath) && !found.has(relPath)) {
            found.add(relPath);
            queue.push(relPath);
        }
    }

    function read(relPath) {
        return fs.readFileSync(path.join(wwwDir, relPath), 'utf8');
    }

    relPaths.filter(function(relPath) {
        return (/\.(js|html?)$/).test(relPath);
    }).forEach(function(relPath) {
        allMatches(/new\s+(?:Shared)?Worker\(\s*(['"])([^'"]+)\1/g, read(relPath)).forEach(function(match) {
            enqueue(path.posix.resolve('/', match[2]));
        });
    });

    function enqueueImports(worker) {
        allMatches(/importScripts\(([^)]*)\)/g, read(worker)).forEach(function(match) {
            stringLiterals(match[1]).forEach(function(literal) {
                enqueue(path.posix.resolve(path.posix.dirname(worker), literal));
            });
        });
    }

    while (queue.length) {
        enqueueImports(queue.shift());
    }
    return Array.from(found);
}

function replaceOnce(content, pattern, replacement) {
    if (!pattern.test(content)) {
        throw new Error('cordova-plugin-crypt-file: ' + LOADER_FILE + ' has no ' + pattern.source + ' slot');
    }
    return content.replace(pattern, function() {
        return replacement;
    });
}

function writeKeysIntoLoader(wwwDir, key, iv, targets) {
    var loaderPath = path.join(wwwDir, LOADER_FILE);
    if (!fs.existsSync(loaderPath)) {
        throw new Error('cordova-plugin-crypt-file: ' + LOADER_FILE +
            ' is missing, this cordova-electron cannot decrypt. Refusing to encrypt.');
    }
    var content = fs.readFileSync(loaderPath, 'utf8');
    content = replaceOnce(content, /CRYPT_KEY = '.*';/, 'CRYPT_KEY = \'' + key + '\';');
    content = replaceOnce(content, /CRYPT_IV = '.*';/, 'CRYPT_IV = \'' + iv + '\';');
    content = replaceOnce(content, /INCLUDE_FILES = \[.*\];/, 'INCLUDE_FILES = ' + JSON.stringify(targets.include) + ';');
    content = replaceOnce(content, /EXCLUDE_FILES = \[.*\];/, 'EXCLUDE_FILES = ' + JSON.stringify(targets.exclude) + ';');
    fs.writeFileSync(loaderPath, content, 'utf8');
}

function protectElectronWww(wwwDir, targetFiles, key, iv, encryptData) {
    var files = listRelativeFiles(wwwDir, '');
    var workerExcludes = findWorkerScripts(wwwDir, files).map(function(relPath) {
        console.log('plain (worker script): ' + relPath);
        return '^' + escapeRegExp(relPath) + '$';
    });
    var targets = electronTargets({ include: targetFiles.include, exclude: targetFiles.exclude.concat(workerExcludes) });
    writeKeysIntoLoader(wwwDir, key, iv, targets);
    files.filter(function(relPath) {
        return isCryptPath(relPath, targets);
    }).forEach(function(relPath) {
        var file = path.join(wwwDir, relPath);
        fs.writeFileSync(file, encryptData(fs.readFileSync(file), key, iv), 'utf8');
        console.log('encrypt: ' + file);
    });
}

module.exports = { protectElectronWww: protectElectronWww };
