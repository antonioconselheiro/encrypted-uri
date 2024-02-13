window.jest_html_reporters_callback__({"numFailedTestSuites":2,"numFailedTests":2,"numPassedTestSuites":1,"numPassedTests":8,"numPendingTestSuites":0,"numPendingTests":22,"numRuntimeErrorTestSuites":0,"numTodoTests":0,"numTotalTestSuites":3,"numTotalTests":32,"startTime":1707825745814,"success":false,"testResults":[{"numFailingTests":1,"numPassingTests":0,"numPendingTests":12,"numTodoTests":0,"perfStats":{"end":1707825755735,"runtime":9037,"slow":true,"start":1707825746698},"testFilePath":"/encrypted-uri/packages/ciphers/kdf.test.ts","failureMessage":"\u001b[1m\u001b[31m  \u001b[1m● \u001b[22m\u001b[1mkdf failure flow › [1] overriding kdf config with wrong default values\u001b[39m\u001b[22m\n\n    \u001b[2mexpect(\u001b[22m\u001b[31mreceived\u001b[39m\u001b[2m).\u001b[22mnot\u001b[2m.\u001b[22mtoEqual\u001b[2m(\u001b[22m\u001b[32mexpected\u001b[39m\u001b[2m) // deep equality\u001b[22m\n\n    Expected: not \u001b[32m\"mensagem secreta, favor não ler em voz alta\"\u001b[39m\n\u001b[2m\u001b[22m\n\u001b[2m    \u001b[0m \u001b[90m 256 |\u001b[39m       derivateKeyLength\u001b[33m:\u001b[39m \u001b[35m32\u001b[39m\u001b[0m\u001b[22m\n\u001b[2m    \u001b[0m \u001b[90m 257 |\u001b[39m     })\u001b[33m;\u001b[39m\u001b[0m\u001b[22m\n\u001b[2m    \u001b[0m\u001b[31m\u001b[1m>\u001b[22m\u001b[2m\u001b[39m\u001b[90m 258 |\u001b[39m     expect(decrypted)\u001b[33m.\u001b[39mnot\u001b[33m.\u001b[39mtoEqual(originalMessage)\u001b[33m;\u001b[39m\u001b[0m\u001b[22m\n\u001b[2m    \u001b[0m \u001b[90m     |\u001b[39m                           \u001b[31m\u001b[1m^\u001b[22m\u001b[2m\u001b[39m\u001b[0m\u001b[22m\n\u001b[2m    \u001b[0m \u001b[90m 259 |\u001b[39m   })\u001b[33m;\u001b[39m\u001b[0m\u001b[22m\n\u001b[2m    \u001b[0m \u001b[90m 260 |\u001b[39m })\u001b[33m;\u001b[39m\u001b[0m\u001b[22m\n\u001b[2m\u001b[22m\n\u001b[2m      \u001b[2mat Object.<anonymous> (\u001b[22m\u001b[2m\u001b[0m\u001b[36mkdf.test.ts\u001b[39m\u001b[0m\u001b[2m:258:27)\u001b[22m\u001b[2m\u001b[22m\n","testResults":[{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [2] kdf include all parameters including default","status":"pending","title":"[2] kdf include all parameters including default"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [3] kdf with hasher sha512","status":"pending","title":"[3] kdf with hasher sha512"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [4] kdf with hasher sha512_256","status":"pending","title":"[4] kdf with hasher sha512_256"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [5] kdf with hasher sha384","status":"pending","title":"[5] kdf with hasher sha384"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [6] kdf with hasher sha3_512","status":"pending","title":"[6] kdf with hasher sha3_512"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [7] kdf with hasher sha3_384","status":"pending","title":"[7] kdf with hasher sha3_384"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [8] kdf with hasher sha3_256","status":"pending","title":"[8] kdf with hasher sha3_256"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [9] kdf with hasher sha3_224","status":"pending","title":"[9] kdf with hasher sha3_224"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [10] kdf with hasher keccak_512","status":"pending","title":"[10] kdf with hasher keccak_512"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [11] kdf with hasher keccak_384","status":"pending","title":"[11] kdf with hasher keccak_384"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [12] kdf with hasher keccak_256","status":"pending","title":"[12] kdf with hasher keccak_256"},{"ancestorTitles":["kdf success flow"],"duration":null,"failureMessages":[],"fullName":"kdf success flow [13] kdf with hasher keccak_224","status":"pending","title":"[13] kdf with hasher keccak_224"},{"ancestorTitles":["kdf failure flow"],"duration":85,"failureMessages":["Error: \u001b[2mexpect(\u001b[22m\u001b[31mreceived\u001b[39m\u001b[2m).\u001b[22mnot\u001b[2m.\u001b[22mtoEqual\u001b[2m(\u001b[22m\u001b[32mexpected\u001b[39m\u001b[2m) // deep equality\u001b[22m\n\nExpected: not \u001b[32m\"mensagem secreta, favor não ler em voz alta\"\u001b[39m\n\n    at Object.<anonymous> (/encrypted-uri/packages/ciphers/kdf.test.ts:258:27)"],"fullName":"kdf failure flow [1] overriding kdf config with wrong default values","status":"failed","title":"[1] overriding kdf config with wrong default values"}]},{"numFailingTests":1,"numPassingTests":5,"numPendingTests":0,"numTodoTests":0,"perfStats":{"end":1707825756082,"runtime":9396,"slow":true,"start":1707825746686},"testFilePath":"/encrypted-uri/packages/ciphers/aes.test.ts","failureMessage":"\u001b[1m\u001b[31m  \u001b[1m● \u001b[22m\u001b[1msuccess flow aes › cbc generated from other implementation with the same algorithm type and params\u001b[39m\u001b[22m\n\n    OperationError: The operation failed for an operation-specific reason\n\u001b[2m\u001b[22m\n\u001b[2m\u001b[22m\n","testResults":[{"ancestorTitles":["success flow aes"],"duration":103,"failureMessages":[],"fullName":"success flow aes cbc","status":"passed","title":"cbc"},{"ancestorTitles":["success flow aes"],"duration":6,"failureMessages":["OperationError: The operation failed for an operation-specific reason\n    at new DOMException (node:internal/per_context/domexception:53:5)\n    at __node_internal_ (node:internal/util:695:10)\n    at AESCipherJob.onDone (node:internal/crypto/util:420:19)"],"fullName":"success flow aes cbc generated from other implementation with the same algorithm type and params","status":"failed","title":"cbc generated from other implementation with the same algorithm type and params"},{"ancestorTitles":["success flow aes"],"duration":13,"failureMessages":[],"fullName":"success flow aes ctr","status":"passed","title":"ctr"},{"ancestorTitles":["success flow aes"],"duration":13,"failureMessages":[],"fullName":"success flow aes ecb","status":"passed","title":"ecb"},{"ancestorTitles":["success flow aes"],"duration":12,"failureMessages":[],"fullName":"success flow aes gcm","status":"passed","title":"gcm"},{"ancestorTitles":["success flow aes"],"duration":19,"failureMessages":[],"fullName":"success flow aes siv","status":"passed","title":"siv"}]},{"numFailingTests":0,"numPassingTests":3,"numPendingTests":10,"numTodoTests":0,"perfStats":{"end":1707825756850,"runtime":10161,"slow":true,"start":1707825746689},"testFilePath":"/encrypted-uri/packages/ciphers/params.test.ts","failureMessage":null,"testResults":[{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [3] kdf with hasher sha512","status":"pending","title":"[3] kdf with hasher sha512"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [4] kdf with hasher sha512_256","status":"pending","title":"[4] kdf with hasher sha512_256"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [5] kdf with hasher sha384","status":"pending","title":"[5] kdf with hasher sha384"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [6] kdf with hasher sha3_512","status":"pending","title":"[6] kdf with hasher sha3_512"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [7] kdf with hasher sha3_384","status":"pending","title":"[7] kdf with hasher sha3_384"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [8] kdf with hasher sha3_256","status":"pending","title":"[8] kdf with hasher sha3_256"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [9] kdf with hasher sha3_224","status":"pending","title":"[9] kdf with hasher sha3_224"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [10] kdf with hasher keccak_512","status":"pending","title":"[10] kdf with hasher keccak_512"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [11] kdf with hasher keccak_384","status":"pending","title":"[11] kdf with hasher keccak_384"},{"ancestorTitles":["hashing customization"],"duration":null,"failureMessages":[],"fullName":"hashing customization [12] kdf with hasher keccak_256","status":"pending","title":"[12] kdf with hasher keccak_256"},{"ancestorTitles":["checking if params are correctly encoded"],"duration":57,"failureMessages":[],"fullName":"checking if params are correctly encoded [1] overriding default values in decrypt","status":"passed","title":"[1] overriding default values in decrypt"},{"ancestorTitles":["checking if params are correctly encoded"],"duration":17,"failureMessages":[],"fullName":"checking if params are correctly encoded [2] kdf include all parameters including default","status":"passed","title":"[2] kdf include all parameters including default"},{"ancestorTitles":["checking if params are correctly encoded"],"duration":9,"failureMessages":[],"fullName":"checking if params are correctly encoded [3] kdf with algorithm not set","status":"passed","title":"[3] kdf with algorithm not set"}]}],"config":{"bail":0,"changedFilesWithAncestor":false,"ci":false,"collectCoverage":false,"collectCoverageFrom":[],"coverageDirectory":"/encrypted-uri/packages/ciphers/coverage","coverageProvider":"babel","coverageReporters":["json","text","lcov","clover"],"detectLeaks":false,"detectOpenHandles":false,"errorOnDeprecated":false,"expand":false,"findRelatedTests":false,"forceExit":false,"json":false,"lastCommit":false,"listTests":false,"logHeapUsage":false,"maxConcurrency":5,"maxWorkers":7,"noStackTrace":false,"nonFlagArgs":[],"notify":false,"notifyMode":"failure-change","onlyChanged":false,"onlyFailures":false,"openHandlesTimeout":1000,"passWithNoTests":false,"projects":[],"reporters":[["default",{}],["/encrypted-uri/packages/ciphers/node_modules/jest-html-reporters/index.js",{"publicPath":"../../docs/ciphers","filename":"test-report.html","expand":true}]],"rootDir":"/encrypted-uri/packages/ciphers","runTestsByPath":false,"seed":-444294862,"skipFilter":false,"snapshotFormat":{"escapeString":false,"printBasicPrototype":false},"testFailureExitCode":1,"testPathPattern":"","testSequencer":"/encrypted-uri/packages/ciphers/node_modules/@jest/test-sequencer/build/index.js","updateSnapshot":"new","useStderr":false,"watch":false,"watchAll":false,"watchman":true,"workerThreads":false},"endTime":1707825756965,"_reporterOptions":{"publicPath":"../../docs/ciphers","filename":"test-report.html","expand":true,"pageTitle":"","hideIcon":false,"testCommand":"","openReport":false,"failureMessageOnly":0,"enableMergeData":false,"dataMergeLevel":1,"inlineSource":false,"urlForTestFiles":"","darkTheme":false,"includeConsoleLog":false,"stripSkippedTest":false},"logInfoMapping":{},"attachInfos":{}})