// --- UTILITIES & ANALYSIS FUNCTIONS ---

let customYaraRules = null;

// [업데이트] 내장 YARA 룰 원본 (수정 용이성을 위해 단순 문자열 배열 유지)
const rawInternalYaraRules = {
    'Suspicious_VBA_Macro_Keywords': {
        description: "악성 VBA 매크로에서 자주 사용되는 키워드를 탐지합니다.",
        author: "Scenario-Based",
        strings: ["Auto_Open", "Workbook_Open", "CreateObject", "WScript.Shell", "powershell.exe", "Run", "Shell", "WinHttpRequest", "Download", "Admin", "UAC"],
        condition: "2" // 2개 이상 일치 시
    },
    'PowerShell_Training_Scenario_Detection': {
        description: "훈련용 PowerShell 스크립트(1~6)에서 발견되는 특정 행위를 탐지합니다. (shell_detect_rule.yar 기반)",
        author: "Training",
        strings: [
            "systeminfo", "Get-Process", "tasklist", "Get-NetTCPConnection",
            "Get-LocalUser", "Get-LocalGroup", "TcpClient", "GetStream",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU", "TcpListener"
        ],
        condition: "any"
    },
    'PE_Header_Signature_Check': {
        description: "파일 헤더에서 PE 파일 시그니처('MZ', 'PE')를 탐지합니다. (pe_detect_rule.yar 기반)",
        author: "Rule-Based",
        strings: ["MZ", "PE"],
        condition: "all" // 두 문자열이 모두 존재해야 탐지
    }
};

// [FIX] 내장 룰을 파서가 사용하는 표준 형식으로 변환하는 함수
function processInternalRules(rawRules) {
    const processedRules = {};
    for (const ruleName in rawRules) {
        const rawRule = rawRules[ruleName];
        processedRules[ruleName] = {
            ...rawRule,
            strings: rawRule.strings.map((str, index) => ({
                type: 'text',
                value: str,
                identifier: `$s${index + 1}`,
                display: `"${str}"`
            }))
        };
    }
    return processedRules;
}

// 변환된 내장 룰을 전역 변수로 사용
const internalYaraRules = processInternalRules(rawInternalYaraRules);


// ArrayBuffer를 CryptoJS WordArray로 변환
function arrayBufferToWordArray(ab) {
    const i8a = new Uint8Array(ab);
    const a = [];
    for (let i = 0; i < i8a.length; i += 4) {
        a.push(i8a[i] << 24 | i8a[i + 1] << 16 | i8a[i + 2] << 8 | i8a[i + 3]);
    }
    return CryptoJS.lib.WordArray.create(a, i8a.length);
}

// 해시 계산
async function calculateHashes(fileData) {
    const wordArray = arrayBufferToWordArray(fileData);
    const md5 = CryptoJS.MD5(wordArray).toString();
    const sha1 = CryptoJS.SHA1(wordArray).toString();
    const sha256 = CryptoJS.SHA256(wordArray).toString();
    return { md5, sha1, sha256 };
}

// PE 파일 분석 (시나리오 기반 강화)
function analyzePeFile(fileName, fileBuffer) {
    const analysis = {
        'Type': 'PE (Portable Executable)',
        '취약점 분석': ['신뢰할 수 없는 출처의 서명되지 않은 실행 파일로, 코드 변조 및 악성 기능 포함 가능성이 높습니다.'],
        '예상 악성 행위': [
            '시스템 정보 및 사용자 계정 정보 수집을 시도합니다.',
            '레지스트리 Run 키 조작을 통해 악성코드 지속성을 확보하려 합니다.',
            '외부 C2 서버와 통신을 위한 네트워크 연결을 시도할 수 있습니다 (ws2_32.dll 임포트).',
            '추가적인 PowerShell 스크립트(.ps1)를 생성하거나 호출하여 2차 공격을 수행할 수 있습니다.'
        ],
        '탐지된 위험 키워드': ['kernel32.dll', 'advapi32.dll', 'ws2_32.dll', 'CreateProcessA', 'RegSetValueExA'],
        'Analysis Note': '브라우저 환경에서는 PE 파일의 상세 정적 분석이 제한됩니다. 이 정보는 일반적인 악성 PE 파일의 특징을 나타내는 예시입니다.'
    };
    const yaraMatches = yaraScan(new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(fileBuffer), fileBuffer);
    if (yaraMatches.length > 0) {
        analysis['YARA Matches'] = yaraMatches.map(m => m.rule);
    }
    return analysis;
}

// 스크립트/텍스트 파일 분석 (시나리오 기반 강화)
function analyzeScriptFile(fileContent, fileName, fileBuffer) {
    const analysis = {};
    const extension = fileName.split('.').pop().toUpperCase();
    analysis['Type'] = extension === 'PS1' ? 'PowerShell Script' : 'Text File';
    
    const keywords = {
        'systeminfo': '시스템 기본 정보 수집',
        'Get-Process': '현재 실행 중인 프로세스 목록 수집',
        'tasklist': '현재 실행 중인 프로세스 목록 수집',
        'Get-NetTCPConnection': '활성 네트워크 연결 정보 수집',
        'Get-LocalUser': '로컬 사용자 계정 목록 수집',
        'Get-LocalGroup': '로컬 그룹 목록 수집',
        'TcpClient': '외부 서버와 TCP 통신 (리버스 쉘 의심)',
        'GetStream': '네트워크 스트림을 이용한 데이터 송수신 (리버스 쉘 의심)',
        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': '레지스트리 Run 키 조작 (지속성 확보 의심)',
        'HKCU': '사용자 레지스트리 키 조작'
    };
    
    const foundKeywords = Object.keys(keywords).filter(kw => fileContent.toLowerCase().includes(kw.toLowerCase()));
    
    if (extension === 'PS1') {
        analysis['취약점 분석'] = ['스크립트 실행 정책 우회(-ExecutionPolicy Bypass)를 통해 시스템 보안 설정을 무력화할 수 있습니다.'];
        analysis['예상 악성 행위'] = foundKeywords.map(kw => keywords[kw]);
    } else { // TXT
        analysis['취약점 분석'] = ['수집된 시스템/사용자 정보가 평문으로 저장되어 있어 유출 시 심각한 위협을 초래할 수 있습니다.'];
        analysis['예상 악성 행위'] = ['악성 행위의 결과물로, 공격자가 탈취하려는 주요 정보가 포함되어 있습니다.'];
    }

    if (foundKeywords.length > 0) {
        analysis['탐지된 위험 키워드'] = foundKeywords;
    }
    
    const yaraMatches = yaraScan(fileContent, fileBuffer);
    if(yaraMatches.length > 0) {
        analysis['YARA Matches'] = yaraMatches.map(m => m.rule);
    }
    
    analysis['Content Preview'] = fileContent;
    return analysis;
}

// XLSM 파일 분석 (시나리오 기반 강화)
function analyzeXlsmFile(fileContent, fileBuffer) {
    const keywords = ["Auto_Open", "Workbook_Open", "CreateObject", "WScript.Shell", "powershell.exe", "Run", "Shell", "WinHttpRequest"];
    const foundKeywords = keywords.filter(kw => fileContent.toLowerCase().includes(kw.toLowerCase()));

    const analysis = {
        'Type': 'Excel (XLSM) with Macro',
        '취약점 분석': ['VBA 매크로 자동 실행 (Workbook_Open/Auto_Open)을 통해 사용자 개입 없이 코드가 실행될 수 있습니다.'],
        '예상 악성 행위': [
            'WScript.Shell 또는 Shell 함수를 이용해 외부 프로세스(powershell.exe)를 실행할 수 있습니다.',
            'WinHttpRequest 객체를 사용해 C2 서버에서 추가 악성 파일을 다운로드할 수 있습니다.'
        ],
        '탐지된 위험 키워드': foundKeywords,
        'Analysis Note': '파일 내부 문자열에서 악성 행위와 관련된 키워드를 검색합니다.'
    };

    const yaraMatches = yaraScan(fileContent, fileBuffer);
    if (yaraMatches.length > 0) {
        analysis['YARA Matches'] = yaraMatches.map(m => m.rule);
    }
    return analysis;
}


// 바이트 배열 검색 헬퍼 함수
function searchForBytes(buffer, sequence) {
    if (sequence.length === 0) return true;
    for (let i = 0; i <= buffer.length - sequence.length; i++) {
        let found = true;
        for (let j = 0; j < sequence.length; j++) {
            if (buffer[i + j] !== sequence[j]) {
                found = false;
                break;
            }
        }
        if (found) return true;
    }
    return false;
}

// YARA 스캔 로직 (바이너리/텍스트 동시 지원)
function yaraScan(textContent, fileBuffer) {
    const rulesToUse = customYaraRules || internalYaraRules;
    const fileBytes = new Uint8Array(fileBuffer);
    const matches = [];

    for (const ruleName in rulesToUse) {
        const rule = rulesToUse[ruleName];
        let matchedStrings = [];

        rule.strings.forEach(strObj => {
            let isMatch = false;
            if (strObj.type === 'hex') {
                isMatch = searchForBytes(fileBytes, strObj.value);
            } else { // type === 'text'
                if (ruleName.toLowerCase().includes('pe')) {
                    isMatch = textContent.includes(strObj.value);
                } else {
                    isMatch = textContent.toLowerCase().includes(strObj.value.toLowerCase());
                }
            }

            if (isMatch) {
                matchedStrings.push({
                    identifier: strObj.identifier,
                    data: strObj.display
                });
            }
        });

        let conditionMet = false;
        if (rule.condition === 'any') {
            conditionMet = matchedStrings.length > 0;
        } else if (rule.condition === 'all') {
            conditionMet = matchedStrings.length === rule.strings.length;
        } else {
            const numCondition = parseInt(rule.condition);
            if (!isNaN(numCondition)) {
                conditionMet = matchedStrings.length >= numCondition;
            }
        }

        if (conditionMet) {
            matches.push({
                rule: ruleName,
                meta: { description: rule.description, author: rule.author },
                strings: matchedStrings
            });
        }
    }
    return matches;
}


// YARA 룰 파서 (타입, 원본 문자열 저장)
function parseYaraRule(ruleContent) {
    const rules = {};
    const ruleRegex = /rule\s+([\w_]+)\s*\{([\s\S]*?)\}/g;
    let match;

    while ((match = ruleRegex.exec(ruleContent)) !== null) {
        const ruleName = match[1];
        const ruleBody = match[2];

        const metaDescMatch = ruleBody.match(/description\s*=\s*"([^"]*)"/);
        const stringsMatch = ruleBody.match(/strings:\s*([\s\S]*?)condition:/);
        const conditionMatch = ruleBody.match(/condition:\s*([\s\S]*?)\s*\}/);

        if (stringsMatch && conditionMatch) {
            const strings = [];
            const stringRegex = /(\$[\w\d_]+)\s*=\s*(?:("([^"]*)")|\{\s*([A-Fa-f0-9\s]+)\s*\})(?:\s*nocase)?/g;
            let stringMatch;
            while ((stringMatch = stringRegex.exec(stringsMatch[1])) !== null) {
                const identifier = stringMatch[1];
                const textValue = stringMatch[3];
                const hexValue = stringMatch[4];

                if (textValue !== undefined) {
                    strings.push({ type: 'text', value: textValue, identifier: identifier, display: `"${textValue}"` });
                } else if (hexValue) {
                    const hexString = hexValue.replace(/\s/g, '');
                    const bytes = new Uint8Array(hexString.length / 2);
                    for (let i = 0; i < hexString.length; i += 2) {
                        bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
                    }
                    strings.push({ type: 'hex', value: bytes, identifier: identifier, display: `{ ${hexValue.trim()} }` });
                }
            }

            let condition = 'any';
            const conditionStr = conditionMatch[1].trim();
            if (conditionStr.includes('all of')) {
                condition = 'all';
            } else {
                 const numMatch = conditionStr.match(/(\d+)\s+of/);
                if (numMatch) condition = numMatch[1];
            }

            if (strings.length > 0) {
                rules[ruleName] = {
                    description: metaDescMatch ? metaDescMatch[1] : "No description",
                    author: "Custom",
                    strings: strings,
                    condition: condition
                };
            }
        }
    }
    return Object.keys(rules).length > 0 ? rules : null;
}

// --- UI 렌더링 함수 ---

function createHashResultHTML(hashes) {
    return `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm mt-2">
            <p class="font-mono text-gray-400 truncate"><strong>MD5:</strong> ${hashes.md5}</p>
            <p class="font-mono text-gray-400 truncate"><strong>SHA256:</strong> ${hashes.sha256}</p>
        </div>
    `;
}

// [신규] 종합 시나리오 분석을 위한 상세 결과 HTML 렌더링 함수
function createDetailedAnalysisHTML(analysis) {
    let html = '';
    const riskKeys = ['취약점 분석', '예상 악성 행위'];
    const tagKeys = ['탐지된 위험 키워드', 'YARA Matches'];

    for (const key in analysis) {
        const value = analysis[key];
        if (!value || (Array.isArray(value) && value.length === 0)) continue;

        html += `<div class="mt-3 p-3 bg-gray-700/50 border border-gray-600 rounded-lg text-sm">`;
        html += `<p class="font-semibold text-gray-300 mb-2">${key}</p>`;

        if (riskKeys.includes(key) && Array.isArray(value)) {
            html += `<ul class="list-disc list-inside space-y-1 pl-2">`;
            value.forEach(item => {
                html += `<li class="text-yellow-300"><i data-lucide="alert-triangle" class="inline w-4 h-4 mr-2 -ml-1"></i>${item}</li>`;
            });
            html += `</ul>`;
        } else if (tagKeys.includes(key) && Array.isArray(value)) {
            html += `<div class="flex flex-wrap gap-2 mt-1">`;
            value.forEach(item => {
                html += `<span class="bg-red-900/70 text-red-300 text-xs font-mono font-medium px-2.5 py-1 rounded-full">${item}</span>`;
            });
            html += `</div>`;
        } else if (key.toLowerCase().includes('preview')) {
            html += `<div class="max-h-48 overflow-y-auto bg-gray-900 rounded-lg p-3 mt-1 border border-gray-700">
                         <pre><code class="text-sm text-gray-300">${String(value).replace(/</g, "&lt;").replace(/>/g, "&gt;")}</code></pre>
                     </div>`;
        } else if (typeof value === 'object' && value !== null) {
             html += `<pre class="whitespace-pre-wrap text-xs text-blue-300 bg-gray-900/50 p-2 rounded">${JSON.stringify(value, null, 2)}</pre>`;
        } else {
             html += `<p class="text-gray-300">${String(value)}</p>`;
        }
        html += `</div>`;
    }
    return html;
}


// 개별 파일 분석을 위한 기본 결과 HTML 렌더링 함수
function createAnalysisResultHTML(analysis) {
    let html = '';
    for (const key in analysis) {
        const value = analysis[key];
        html += `<div class="mt-2 p-3 bg-gray-700/50 border border-gray-600 rounded-lg text-sm">`;
        if (typeof value === 'object' && value !== null) {
            html += `<p class="text-gray-300 font-semibold">${key}:</p>`;
            html += `<div class="pl-4 mt-1">`;
            if (Array.isArray(value)) {
                html += `<p class="font-mono text-yellow-400">${value.join(', ')}</p>`;
            } else {
                html += `<pre class="whitespace-pre-wrap text-xs text-blue-300">${JSON.stringify(value, null, 2)}</pre>`;
            }
            html += `</div>`;
        } else {
            if (key.toLowerCase().includes('preview')) {
                html += `<p class="text-gray-300 font-semibold">${key}:</p>
                 <div class="max-h-48 overflow-y-auto bg-gray-900 rounded-lg p-3 mt-1 border border-gray-700">
                     <pre><code class="text-sm text-gray-300">${String(value).replace(/</g, "&lt;").replace(/>/g, "&gt;")}</code></pre>
                 </div>`;
            } else {
                html += `<p class="text-gray-300"><span class="font-semibold">${key}:</span> ${String(value)}</p>`;
            }
        }
        html += `</div>`;
    }
    return html;
}


// --- 메인 로직 및 이벤트 핸들러 ---

document.addEventListener('DOMContentLoaded', () => {
    const views = {
        scenario: document.getElementById('view-scenario'),
        single: document.getElementById('view-single'),
        yara: document.getElementById('view-yara')
    };
    const navItems = {
        scenario: document.getElementById('nav-scenario'),
        single: document.getElementById('nav-single'),
        yara: document.getElementById('nav-yara')
    };

    function switchView(viewName) {
        Object.values(views).forEach(v => v.classList.add('hidden'));
        Object.values(navItems).forEach(n => n.classList.remove('active'));
        views[viewName].classList.remove('hidden');
        navItems[viewName].classList.add('active');
        lucide.createIcons();
    }

    navItems.scenario.addEventListener('click', (e) => { e.preventDefault(); switchView('scenario'); });
    navItems.single.addEventListener('click', (e) => { e.preventDefault(); switchView('single'); });
    navItems.yara.addEventListener('click', (e) => { e.preventDefault(); switchView('yara'); });

    setupFileHandler('xlsm', handleFileAnalysis, document.getElementById('result-xlsm'));
    setupFileHandler('exe', handleFileAnalysis, document.getElementById('result-exe'));
    setupFileHandler('ps1', handleFileAnalysis, document.getElementById('result-ps1'));
    setupFileHandler('txt', handleFileAnalysis, document.getElementById('result-txt'));
    setupFileHandler('single', handleFileAnalysis, document.getElementById('result-single'));
    setupFileHandler('yar', handleYaraRuleFile, null);
    setupFileHandler('yara-target', (file, data) => { }, null);

    document.getElementById('scan-btn-yara').addEventListener('click', handleYaraScan);

    updateYaraAccordion();
    lucide.createIcons();
});

function setupFileHandler(id, callback, resultEl) {
    const fileInput = document.getElementById(`file-${id}`);
    const dropZone = document.getElementById(`drop-zone-${id}`);
    const filenameDisplay = document.getElementById(`filename-${id}`);
    if (!fileInput || !dropZone || !filenameDisplay) return;

    const processFile = (file) => {
        if (!file) return;
        filenameDisplay.textContent = `'${file.name}' 파일 처리 중...`;
        const reader = new FileReader();
        reader.onload = (e) => {
            callback(file, e.target.result, resultEl);
            lucide.createIcons();
        };
        reader.readAsArrayBuffer(file);
    };

    fileInput.addEventListener('change', () => processFile(fileInput.files[0]));
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => { e.preventDefault(); e.stopPropagation(); });
        if(eventName === 'dragenter' || eventName === 'dragover'){
            dropZone.addEventListener(eventName, () => dropZone.classList.add('bg-gray-700', 'border-blue-500'));
        }
        if(eventName === 'dragleave' || eventName === 'drop'){
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('bg-gray-700', 'border-blue-500'));
        }
    });
    dropZone.addEventListener('drop', (e) => {
        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            processFile(e.dataTransfer.files[0]);
        }
    });
}

// [수정] 뷰에 따라 다른 렌더링 함수를 사용하도록 핸들러 업데이트
async function handleFileAnalysis(file, fileBuffer, resultEl) {
    const filenameDisplay = resultEl.previousElementSibling.querySelector('p[id^="filename-"]');
    filenameDisplay.textContent = `'${file.name}' 파일 분석 중...`;

    const hashes = await calculateHashes(fileBuffer);
    const extension = file.name.split('.').pop().toLowerCase();
    const textContent = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(fileBuffer);
    let analysis;
    
    if (extension === 'exe' || extension === 'dll') {
        analysis = analyzePeFile(file.name, fileBuffer);
    } else if (['ps1', 'txt', 'yar', 'yara'].includes(extension)) {
        analysis = analyzeScriptFile(textContent, file.name, fileBuffer);
    } else if (extension === 'xlsm') {
        analysis = analyzeXlsmFile(textContent, fileBuffer);
    } else {
        const yaraMatches = yaraScan(textContent, fileBuffer);
        analysis = { 'Info': `.${extension} 파일에 대한 특화된 분석 기능은 없습니다.` };
        if(yaraMatches.length > 0) analysis['YARA Matches'] = yaraMatches.map(m => m.rule);
    }

    if (resultEl.id === 'result-single') {
        let analysisHTML = `<h3 class="text-xl font-semibold mt-6 mb-4">📄 기본 정보</h3>
            <div class="bg-gray-800 rounded-lg p-4 grid grid-cols-2 gap-4">
                <p><strong>파일 이름:</strong> ${file.name}</p><p><strong>파일 크기:</strong> ${file.size} Bytes</p>
            </div>
            <h3 class="text-xl font-semibold mt-6 mb-4">#️⃣ 해시 값</h3>
            <div class="bg-gray-800 rounded-lg p-4 font-mono text-sm space-y-2">
                <div><label class="font-bold text-gray-400">MD5:</label><input type="text" readonly value="${hashes.md5}" class="w-full bg-gray-700 p-1 rounded mt-1 text-gray-200"></div>
                <div><label class="font-bold text-gray-400">SHA1:</label><input type="text" readonly value="${hashes.sha1}" class="w-full bg-gray-700 p-1 rounded mt-1 text-gray-200"></div>
                <div><label class="font-bold text-gray-400">SHA256:</label><input type="text" readonly value="${hashes.sha256}" class="w-full bg-gray-700 p-1 rounded mt-1 text-gray-200"></div>
            </div>
            <h3 class="text-xl font-semibold mt-6 mb-4">🔬 상세 분석 결과</h3>`;
        analysisHTML += createAnalysisResultHTML(analysis);
        resultEl.innerHTML = analysisHTML;
    } else {
        // 종합 시나리오 분석 뷰
        resultEl.innerHTML = createHashResultHTML(hashes) + createDetailedAnalysisHTML(analysis);
    }

    filenameDisplay.textContent = `'${file.name}' 분석 완료.`;
    lucide.createIcons();
}

function handleYaraRuleFile(file, fileBuffer) {
    const filenameDisplay = document.getElementById('filename-yar');
    const yaraStatus = document.getElementById('yara-source-name');
    filenameDisplay.textContent = `룰 파일 '${file.name}' 로딩 중...`;
    const textContent = new TextDecoder("utf-8").decode(fileBuffer);
    const parsedRules = parseYaraRule(textContent);

    if (parsedRules) {
        customYaraRules = parsedRules;
        filenameDisplay.textContent = `'${file.name}' 룰셋이 적용되었습니다.`;
        yaraStatus.textContent = `커스텀 룰 (${file.name})`;
        yaraStatus.classList.remove('text-blue-400');
        yaraStatus.classList.add('text-green-400');
    } else {
        customYaraRules = null; // 실패 시 내장 룰로 복귀
        filenameDisplay.textContent = `'${file.name}'에서 유효한 룰을 찾지 못했습니다. 내장 룰을 사용합니다.`;
        yaraStatus.textContent = '기본 내장 룰 (커스텀 룰 로드 실패)';
        yaraStatus.classList.add('text-blue-400');
        yaraStatus.classList.remove('text-green-400');
    }
    updateYaraAccordion();
}

function handleYaraScan() {
    const fileInput = document.getElementById('file-yara-target');
    const resultEl = document.getElementById('result-yara');
    if (!fileInput.files || fileInput.files.length === 0) {
        resultEl.innerHTML = `<div class="p-4 bg-yellow-900/50 border border-yellow-700 rounded-lg text-yellow-300">스캔할 파일을 먼저 업로드하세요.</div>`;
        return;
    }
    const file = fileInput.files[0];
    const reader = new FileReader();
    reader.onload = (e) => {
        const fileBuffer = e.target.result;
        const textContent = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(fileBuffer);
        const matches = yaraScan(textContent, fileBuffer);

        let resultHTML = `<h3 class="text-xl font-semibold mb-4">📊 YARA 스캔 결과 (${file.name})</h3>`;
        if (matches.length > 0) {
            resultHTML += `<div class="p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-300 mb-4"><strong><i data-lucide="shield-alert" class="inline w-5 h-5 mr-1"></i>탐지됨!</strong> - ${matches.length}개 규칙과 일치합니다:</div>`;
            matches.forEach(match => {
                resultHTML += `<div class="bg-gray-800 rounded-lg p-4 mb-3">
                    <p class="font-bold text-lg text-red-400">${match.rule}</p>
                    <p class="text-sm text-gray-400 mb-2">${match.meta.description}</p>
                    <div class="font-mono text-xs bg-gray-900 p-2 rounded">
                        ${match.strings.map(s => `<p><span class="text-blue-400">${s.identifier}:</span> <span class="text-gray-300">'${s.data.substring(0, 80)}'</span></p>`).join('')}
                    </div></div>`;
            });
        } else {
            resultHTML += `<div class="p-4 bg-green-900/50 border border-green-700 rounded-lg text-green-300"><strong><i data-lucide="shield-check" class="inline w-5 h-5 mr-1"></i>탐지되지 않음</strong> - 적용된 YARA 룰과 일치하는 패턴을 찾지 못했습니다.</div>`;
        }
        resultEl.innerHTML = resultHTML;
        lucide.createIcons();
    };
    reader.readAsArrayBuffer(file);
}

function updateYaraAccordion() {
    const yaraAccordion = document.getElementById('yara-rules-accordion');
    yaraAccordion.innerHTML = '';
    const rulesToDisplay = customYaraRules || internalYaraRules;

    Object.keys(rulesToDisplay).forEach(ruleName => {
        const rule = rulesToDisplay[ruleName];
        const ruleElement = document.createElement('div');
        ruleElement.className = 'border-b border-gray-700';
        ruleElement.innerHTML = `
            <button class="w-full text-left p-3 hover:bg-gray-700 transition flex justify-between items-center">
                <span class="font-semibold">${ruleName}</span>
                <i data-lucide="chevron-down" class="w-5 h-5 transition-transform"></i>
            </button>
            <div class="expander-content px-4 pb-4 bg-gray-900/50">
                <p class="text-sm text-gray-400 mb-2"><strong>설명:</strong> ${rule.description}</p>
                <p class="text-sm text-gray-400 mb-2"><strong>탐지 문자열 (${rule.condition} 조건):</strong></p>
                <div class="font-mono text-xs text-blue-300">${rule.strings.map(s => s.display).join(', ')}</div>
            </div>`;
        yaraAccordion.appendChild(ruleElement);
    });

    yaraAccordion.removeEventListener('click', toggleAccordion);
    yaraAccordion.addEventListener('click', toggleAccordion);
    lucide.createIcons();
}

function toggleAccordion(e) {
    const button = e.target.closest('button');
    if (button) {
        const content = button.nextElementSibling;
        const icon = button.querySelector('i');
        if (content.style.maxHeight) {
            content.style.maxHeight = null;
            icon.style.transform = 'rotate(0deg)';
        } else {
            content.style.maxHeight = content.scrollHeight + "px";
            icon.style.transform = 'rotate(180deg)';
        }
    }
}

