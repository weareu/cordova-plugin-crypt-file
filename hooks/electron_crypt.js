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
    var targets = electronTargets(targetFiles);
    writeKeysIntoLoader(wwwDir, key, iv, targets);
    listRelativeFiles(wwwDir, '').filter(function(relPath) {
        return isCryptPath(relPath, targets);
    }).forEach(function(relPath) {
        var file = path.join(wwwDir, relPath);
        fs.writeFileSync(file, encryptData(fs.readFileSync(file), key, iv), 'utf8');
        console.log('encrypt: ' + file);
    });
}

module.exports = { protectElectronWww: protectElectronWww };
