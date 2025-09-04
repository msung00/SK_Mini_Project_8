// --- UTILITIES & ANALYSIS FUNCTIONS ---

const internalYaraRules = {
    'Suspicious_PowerShell': {
        description: "Detects suspicious PowerShell keywords",
        author: "Gemini",
        strings: ["Invoke-Expression", "IEX", "DownloadFile", "bypass"],
        condition: "any"
    },
    'Suspicious_VBA_Macro': {
        description: "Detects keywords often used in malicious VBA macros",
        author: "Gemini",
        strings: ["Auto_Open", "Workbook_Open", "CreateObject", "WScript.Shell", "powershell"],
        condition: "2"
    },
    'Info_Gathering_Commands': {
        description: "Detects common information gathering commands",
        author: "Gemini",
        strings: ["whoami", "systeminfo", "ipconfig", "tasklist", "net user"],
        condition: "2"
    }
};

// Convert ArrayBuffer to CryptoJS WordArray
function arrayBufferToWordArray(ab) {
    const i8a = new Uint8Array(ab);
    const a = [];
    for (let i = 0; i < i8a.length; i += 4) {
        a.push(i8a[i] << 24 | i8a[i + 1] << 16 | i8a[i + 2] << 8 | i8a[i + 3]);
    }
    return CryptoJS.lib.WordArray.create(a, i8a.length);
}

// Calculate Hashes
async function calculateHashes(fileData) {
    const wordArray = arrayBufferToWordArray(fileData);
    const md5 = CryptoJS.MD5(wordArray).toString();
    const sha1 = CryptoJS.SHA1(wordArray).toString();
    const sha256 = CryptoJS.SHA256(wordArray).toString();
    return { md5, sha1, sha256 };
}

// Analyze PE File (Simplified for Browser)
function analyzePeFile(fileName) {
    // NOTE: Full PE parsing is complex in browser-side JS without heavy libraries.
    // This provides a simplified, representative analysis.
    const analysis = {
        'type': 'PE (Executable)',
        '컴파일 시간': 'N/A (브라우저에서 분석 불가)',
        '아키텍처': 'N/A (브라우저에서 분석 불가)',
        '섹션 정보': 'N/A (브라우저에서 분석 불가)',
        '임포트 정보': {
            'kernel32.dll': ['CreateFileA', 'WriteFile', '... (예시)'],
            'advapi32.dll': ['RegOpenKeyExA', '... (예시)'],
            'user32.dll': ['MessageBoxA', '... (예시)']
        },
        'analysis_note': '브라우저 환경에서는 PE 파일의 상세한 정적 분석이 제한됩니다. 이 정보는 일반적인 악성 PE 파일의 예시입니다.'
    };
    return analysis;
}

// Analyze Script/Text File
function analyzeScriptFile(fileContent, fileName) {
    const analysis = {};
    const extension = fileName.split('.').pop().toUpperCase();
    analysis['type'] = extension === 'PS1' ? 'PowerShell Script' : 'Text File';
    analysis['content'] = fileContent;

    const suspiciousKeywords = [
        'Invoke-Expression', 'IEX', 'Invoke-Command', 'Invoke-WebRequest', 'DownloadFile',
        'Start-Process', 'bypass', 'Set-MpPreference', 'AMSI', 'Set-ItemProperty', 
        'reg add', 'schtasks', 'net user', 'net group', 'whoami', 'ipconfig', 
        'systeminfo', 'tasklist', 'mimikatz', 'lsass', 'powershell'
    ];
    
    const foundKeywords = suspiciousKeywords.filter(kw => fileContent.toLowerCase().includes(kw.toLowerCase()));
    analysis['의심 키워드'] = foundKeywords;
    return analysis;
}

// Analyze XLSM File (String-based keyword search)
function analyzeXlsmFile(fileContent) {
    const analysis = { 'type': 'Excel (XLSM)' };
    const suspiciousKeywords = [
        'Shell', 'CreateObject', 'WScript.Shell', 'Run', 'Workbook_Open', 'Auto_Open',
        'powershell', 'cmd.exe', 'WinHttpRequest', 'MSXML2.XMLHTTP', 'http',
        'FileSystemObject', 'Kill', 'Chr', 'Asc', 'Base64'
    ];
    
    const foundKeywords = suspiciousKeywords.filter(kw => fileContent.toLowerCase().includes(kw.toLowerCase()));
    analysis['매크로 의심 키워드'] = foundKeywords;
    return analysis;
}

// YARA Scan Simulation
function yaraScan(fileContent) {
    const matches = [];
    for (const ruleName in internalYaraRules) {
        const rule = internalYaraRules[ruleName];
        let matchedStrings = [];
        
        rule.strings.forEach(str => {
            if (fileContent.toLowerCase().includes(str.toLowerCase())) {
                matchedStrings.push({identifier: str, data: str});
            }
        });

        const conditionMet = 
            (rule.condition === 'any' && matchedStrings.length > 0) ||
            (parseInt(rule.condition) && matchedStrings.length >= parseInt(rule.condition));

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

// --- UI RENDERING FUNCTIONS ---

function createHashResultHTML(hashes) {
    return `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm mt-2">
            <p class="font-mono text-gray-400 truncate"><strong>MD5:</strong> ${hashes.md5}</p>
            <p class="font-mono text-gray-400 truncate"><strong>SHA256:</strong> ${hashes.sha256}</p>
        </div>
    `;
}

function createKeywordWarningHTML(title, keywords) {
    if (keywords && keywords.length > 0) {
        return `
            <div class="mt-2 p-3 bg-yellow-900/50 border border-yellow-700 rounded-lg text-sm">
                <p class="text-yellow-300"><i data-lucide="alert-triangle" class="inline w-4 h-4 mr-1"></i><strong>${title}:</strong> 다음 의심 키워드가 발견되었습니다: <span class="font-mono">${keywords.join(', ')}</span></p>
            </div>
        `;
    }
    return `
        <div class="mt-2 p-3 bg-green-900/50 border border-green-700 rounded-lg text-sm">
            <p class="text-green-300"><i data-lucide="check-circle" class="inline w-4 h-4 mr-1"></i><strong>${title}:</strong> 특별한 의심 키워드가 발견되지 않았습니다.</p>
        </div>
    `;
}

function createPeAnalysisSummaryHTML(analysis) {
    return `
        <div class="mt-2 p-3 bg-blue-900/50 border border-blue-700 rounded-lg text-sm">
             <p class="text-blue-300"><i data-lucide="info" class="inline w-4 h-4 mr-1"></i><strong>PE 분석:</strong> 시스템 제어와 관련된 의심스러운 DLL(kernel32.dll, advapi32.dll)을 임포트합니다. (예시)</p>
        </div>
    `;
}

function createCodeBlockHTML(content, language) {
    return `
         <div class="mt-4">
             <p class="text-sm font-semibold mb-2">파일 내용 미리보기:</p>
             <div class="max-h-48 overflow-y-auto bg-gray-900 rounded-lg p-3 border border-gray-700">
                 <pre><code class="text-sm text-gray-300">${content.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</code></pre>
             </div>
         </div>
    `;
}

// --- MAIN LOGIC & EVENT HANDLERS ---

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

    // Navigation
    function switchView(viewName) {
        Object.values(views).forEach(v => v.classList.add('hidden'));
        Object.values(navItems).forEach(n => n.classList.remove('active'));
        views[viewName].classList.remove('hidden');
        navItems[viewName].classList.add('active');
    }

    navItems.scenario.addEventListener('click', (e) => { e.preventDefault(); switchView('scenario'); });
    navItems.single.addEventListener('click', (e) => { e.preventDefault(); switchView('single'); });
    navItems.yara.addEventListener('click', (e) => { e.preventDefault(); switchView('yara'); });

    // Setup file handlers
    setupFileHandler('xlsm', handleXlsmFile);
    setupFileHandler('exe', handleExeFile);
    setupFileHandler('ps1', handlePs1File);
    setupFileHandler('txt', handleTxtFile);
    setupFileHandler('single', handleSingleFile);
    setupFileHandler('yara', (file, data) => { /* Only button handles this */ });
    
    // YARA scan button
    document.getElementById('scan-btn-yara').addEventListener('click', handleYaraScan);

    // Populate YARA rules
    const yaraAccordion = document.getElementById('yara-rules-accordion');
    Object.keys(internalYaraRules).forEach(ruleName => {
        const rule = internalYaraRules[ruleName];
        const ruleElement = document.createElement('div');
        ruleElement.className = 'border-b border-gray-700';
        ruleElement.innerHTML = `
            <button class="w-full text-left p-3 hover:bg-gray-700 transition flex justify-between items-center">
                <span class="font-semibold">${ruleName}</span>
                <i data-lucide="chevron-down" class="w-5 h-5 transition-transform"></i>
            </button>
            <div class="expander-content px-4 pb-4 bg-gray-900/50">
                <p class="text-sm text-gray-400 mb-2"><strong>설명:</strong> ${rule.description}</p>
                <div class="font-mono text-xs text-blue-300">${rule.strings.join(', ')}</div>
            </div>
        `;
        yaraAccordion.appendChild(ruleElement);
    });

    yaraAccordion.addEventListener('click', (e) => {
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
    });

    lucide.createIcons();
});

function setupFileHandler(id, callback) {
    const fileInput = document.getElementById(`file-${id}`);
    const dropZone = document.getElementById(`drop-zone-${id}`);
    const filenameDisplay = document.getElementById(`filename-${id}`);

    const processFile = (file) => {
        if (!file) return;
        filenameDisplay.textContent = `'${file.name}' 파일이 선택되었습니다. 분석 중...`;
        const reader = new FileReader();
        reader.onload = (e) => {
            callback(file, e.target.result);
            lucide.createIcons();
        };
        // Read as ArrayBuffer for hashing and binary analysis
        // Text analysis functions can convert this buffer to string
        reader.readAsArrayBuffer(file);
    };
    
    fileInput.addEventListener('change', () => processFile(fileInput.files[0]));

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('bg-gray-700', 'border-blue-500'), false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('bg-gray-700', 'border-blue-500'), false);
    });

    dropZone.addEventListener('drop', (e) => {
        let dt = e.dataTransfer;
        let files = dt.files;
        fileInput.files = files;
        processFile(files[0]);
    });
}

// Specific file handlers
async function handleXlsmFile(file, data) {
    const resultEl = document.getElementById('result-xlsm');
    const hashes = await calculateHashes(data);
    const textContent = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(data);
    const analysis = analyzeXlsmFile(textContent);

    resultEl.innerHTML = createHashResultHTML(hashes) + createKeywordWarningHTML('매크로 분석', analysis['매크로 의심 키워드']);
    document.getElementById('filename-xlsm').textContent = `'${file.name}' 분석 완료.`;
}

async function handleExeFile(file, data) {
    const resultEl = document.getElementById('result-exe');
    const hashes = await calculateHashes(data);
    const analysis = analyzePeFile(file.name);
    
    resultEl.innerHTML = createHashResultHTML(hashes) + createPeAnalysisSummaryHTML(analysis);
    document.getElementById('filename-exe').textContent = `'${file.name}' 분석 완료.`;
}

async function handlePs1File(file, data) {
    const resultEl = document.getElementById('result-ps1');
    const textContent = new TextDecoder("utf-8").decode(data);
    const analysis = analyzeScriptFile(textContent, file.name);

    resultEl.innerHTML = createKeywordWarningHTML('스크립트 분석', analysis['의심 키워드']) + createCodeBlockHTML(analysis.content, 'powershell');
    document.getElementById('filename-ps1').textContent = `'${file.name}' 분석 완료.`;
}

async function handleTxtFile(file, data) {
    const resultEl = document.getElementById('result-txt');
    const textContent = new TextDecoder("utf-8").decode(data);
    const analysis = analyzeScriptFile(textContent, file.name);

    resultEl.innerHTML = createKeywordWarningHTML('로그 분석', analysis['의심 키워드']) + createCodeBlockHTML(analysis.content, 'text');
    document.getElementById('filename-txt').textContent = `'${file.name}' 분석 완료.`;
}

async function handleSingleFile(file, data) {
    const resultEl = document.getElementById('result-single');
    const hashes = await calculateHashes(data);
    const extension = file.name.split('.').pop().toLowerCase();
    
    let analysisHTML = `<h3 class="text-xl font-semibold mt-6 mb-4">📄 기본 정보</h3>
    <div class="bg-gray-800 rounded-lg p-4">
        <p><strong>파일 이름:</strong> ${file.name}</p>
        <p><strong>파일 크기:</strong> ${file.size} Bytes</p>
    </div>
    <h3 class="text-xl font-semibold mt-6 mb-4">#️⃣ 해시 값</h3>
    <div class="bg-gray-800 rounded-lg p-4 font-mono text-sm space-y-2">
        <div><label class="font-bold text-gray-400">MD5:</label><input type="text" readonly value="${hashes.md5}" class="w-full bg-gray-700 p-1 rounded mt-1 text-gray-200"></div>
        <div><label class="font-bold text-gray-400">SHA1:</label><input type="text" readonly value="${hashes.sha1}" class="w-full bg-gray-700 p-1 rounded mt-1 text-gray-200"></div>
        <div><label class="font-bold text-gray-400">SHA256:</label><input type="text" readonly value="${hashes.sha256}" class="w-full bg-gray-700 p-1 rounded mt-1 text-gray-200"></div>
    </div>
    <h3 class="text-xl font-semibold mt-6 mb-4">🔬 상세 분석 결과</h3>
    `;

    if (extension === 'exe' || extension === 'dll') {
        const analysis = analyzePeFile(file.name);
        analysisHTML += `<div class="bg-gray-800 rounded-lg p-4"><pre class="text-sm whitespace-pre-wrap">${JSON.stringify(analysis, null, 2)}</pre></div>`;
    } else if (extension === 'ps1' || extension === 'txt') {
        const textContent = new TextDecoder("utf-8").decode(data);
        const analysis = analyzeScriptFile(textContent, file.name);
        analysisHTML += createKeywordWarningHTML('스크립트 분석', analysis['의심 키워드']) + createCodeBlockHTML(analysis.content, extension === 'ps1' ? 'powershell' : 'text');
    } else if (extension === 'xlsm') {
        const textContent = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(data);
        const analysis = analyzeXlsmFile(textContent);
        analysisHTML += createKeywordWarningHTML('매크로 분석', analysis['매크로 의심 키워드']);
    } else {
        analysisHTML += `<p class="p-4 bg-gray-800 rounded-lg">.${extension} 타입 파일에 대한 특화된 분석 기능은 없습니다.</p>`;
    }
    
    resultEl.innerHTML = analysisHTML;
    document.getElementById('filename-single').textContent = `'${file.name}' 분석 완료.`;
    lucide.createIcons();
}

function handleYaraScan() {
    const fileInput = document.getElementById('file-yara');
    const resultEl = document.getElementById('result-yara');
    if (!fileInput.files || fileInput.files.length === 0) {
        resultEl.innerHTML = `<div class="p-4 bg-yellow-900/50 border border-yellow-700 rounded-lg text-yellow-300">스캔할 파일을 먼저 업로드하세요.</div>`;
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();
    reader.onload = (e) => {
        const textContent = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(e.target.result);
        const matches = yaraScan(textContent);

        let resultHTML = `<h3 class="text-xl font-semibold mb-4">📊 스캔 결과</h3>`;
        if (matches.length > 0) {
            resultHTML += `<div class="p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-300 mb-4"><strong>탐지됨!</strong> - 다음 ${matches.length}개 규칙과 일치합니다:</div>`;
            matches.forEach(match => {
                resultHTML += `
                    <div class="bg-gray-800 rounded-lg p-4 mb-3">
                        <p class="font-bold text-lg text-red-400">${match.rule}</p>
                        <p class="text-sm text-gray-400 mb-2">${match.meta.description}</p>
                        <div class="font-mono text-xs bg-gray-900 p-2 rounded">
                            ${match.strings.map(s => `<p><span class="text-blue-400">${s.identifier}:</span> <span class="text-gray-300">${s.data.substring(0, 50)}...</span></p>`).join('')}
                        </div>
                    </div>
                `;
            });
        } else {
            resultHTML += `<div class="p-4 bg-green-900/50 border border-green-700 rounded-lg text-green-300"><strong>탐지되지 않음</strong> - 내장된 YARA 룰과 일치하는 패턴을 찾지 못했습니다.</div>`;
        }
        resultEl.innerHTML = resultHTML;
        lucide.createIcons();
    };
    reader.readAsArrayBuffer(file);
}
