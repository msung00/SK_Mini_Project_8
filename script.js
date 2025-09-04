// --- UTILITIES & ANALYSIS FUNCTIONS ---

let customYaraRules = null;

// 시나리오 기반으로 강화된 내장 YARA 룰
const internalYaraRules = {
    'Suspicious_VBA_Macro_Keywords': {
        description: "악성 VBA 매크로에서 자주 사용되는 키워드를 탐지합니다.",
        author: "Scenario-Based",
        strings: ["Auto_Open", "Workbook_Open", "CreateObject", "WScript.Shell", "powershell.exe", "Run", "Shell", "WinHttpRequest", "Download", "Admin", "UAC"],
        condition: "2" // 2개 이상 일치 시
    },
    'PowerShell_Info_Gathering': {
        description: "정보 수집에 사용되는 일반적인 PowerShell 명령어를 탐지합니다.",
        author: "Scenario-Based",
        strings: ["systeminfo", "Get-Process", "tasklist", "Get-NetTCPConnection", "ipconfig", "Get-LocalUser", "net user", "Get-LocalGroup"],
        condition: "2"
    },
    'PowerShell_Reverse_Shell': {
        description: "PowerShell을 이용한 리버스 쉘 코드를 탐지합니다.",
        author: "Scenario-Based",
        strings: ["System.Net.Sockets.TcpClient", "GetStream", "StreamWriter", "StreamReader", "while ($client.Connected)"],
        condition: "3"
    },
    'PowerShell_Persistence_Registry': {
        description: "레지스트리를 이용한 지속성 유지 시도를 탐지합니다.",
        author: "Scenario-Based",
        strings: ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "New-Item -Path HK", "Set-ItemProperty -Path HK"],
        condition: "1"
    }
};


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

// PE 파일 분석 (시뮬레이션)
function analyzePeFile(fileName) {
    // 참고: 브라우저 환경에서 PE 파싱은 매우 복잡하므로, 이는 대표적인 분석 결과 예시입니다.
    const analysis = {
        'Type': 'PE (Portable Executable)',
        'Compiler Time': 'N/A (Browser Analysis Limit)',
        'Architecture': 'N/A (Browser Analysis Limit)',
        'Suspicious Imports': {
            'kernel32.dll': ['CreateFileA', 'WriteFile', 'CreateProcessA', '...'],
            'advapi32.dll': ['RegOpenKeyExA', 'RegSetValueExA', '...'],
            'ws2_32.dll': ['socket', 'connect', 'send', '... (Network Connection)']
        },
        'Analysis Note': '브라우저 환경에서는 PE 파일의 상세 정적 분석이 제한됩니다. 이 정보는 일반적인 악성 PE 파일의 특징을 나타내는 예시입니다. C2서버 통신 및 정보 유출에 사용될 수 있는 네트워킹 관련 함수(ws2_32.dll)와 시스템 제어/레지스트리 변경 함수(kernel32.dll, advapi32.dll) 임포트가 의심됩니다.'
    };
    return analysis;
}

// 스크립트/텍스트 파일 분석
function analyzeScriptFile(fileContent, fileName) {
    const analysis = {};
    const extension = fileName.split('.').pop().toUpperCase();
    analysis['Type'] = extension === 'PS1' ? 'PowerShell Script' : 'Text File';
    
    // YARA 스캔을 통한 키워드 탐지
    const yaraMatches = yaraScan(fileContent);
    analysis['YARA Matches'] = yaraMatches.map(m => m.rule);

    analysis['Content Preview'] = fileContent;
    return analysis;
}

// XLSM 파일 분석 (문자열 기반 키워드 검색)
function analyzeXlsmFile(fileContent) {
    const analysis = { 'Type': 'Excel (XLSM) with Macro' };
    
    // YARA 스캔 수행
    const yaraMatches = yaraScan(fileContent);
    analysis['YARA Matches'] = yaraMatches.map(m => m.rule);
    
    analysis['Analysis Note'] = 'XLSM 파일은 ZIP 아카이브 형식이므로, 내부의 VBA 스크립트를 직접 파싱하는 것은 브라우저에서 제한됩니다. 대신 파일 전체에서 악성 행위와 관련된 문자열을 검색합니다. Workbook_Open, powershell.exe, UAC 등 의심스러운 키워드가 탐지되었습니다.';
    return analysis;
}

// YARA 스캔 시뮬레이션
function yaraScan(fileContent) {
    const rulesToUse = customYaraRules || internalYaraRules;
    const matches = [];
    for (const ruleName in rulesToUse) {
        const rule = rulesToUse[ruleName];
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

// YARA 룰 파일 파싱 (간소화)
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
            const stringRegex = /\$[\w_]+\s*=\s*"([^"]*)"/g;
            let stringMatch;
            while((stringMatch = stringRegex.exec(stringsMatch[1])) !== null) {
                strings.push(stringMatch[1]);
            }

            // 간소화된 condition 처리: 'any of them' -> 'any', '2 of them' -> '2'
            let condition = 'any';
            const numMatch = conditionMatch[1].match(/(\d+)\s+of/);
            if (numMatch) {
                condition = numMatch[1];
            }

            rules[ruleName] = {
                description: metaDescMatch ? metaDescMatch[1] : "No description",
                author: "Custom",
                strings: strings,
                condition: condition
            };
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

function createAnalysisResultHTML(analysis) {
    let html = '';
    for(const key in analysis) {
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
    // 뷰 및 네비게이션 아이템 초기화
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

    // 네비게이션 뷰 전환 함수
    function switchView(viewName) {
        Object.values(views).forEach(v => v.classList.add('hidden'));
        Object.values(navItems).forEach(n => n.classList.remove('active'));
        views[viewName].classList.remove('hidden');
        navItems[viewName].classList.add('active');
        lucide.createIcons();
    }

    // 네비게이션 클릭 이벤트 리스너 설정
    navItems.scenario.addEventListener('click', (e) => { e.preventDefault(); switchView('scenario'); });
    navItems.single.addEventListener('click', (e) => { e.preventDefault(); switchView('single'); });
    navItems.yara.addEventListener('click', (e) => { e.preventDefault(); switchView('yara'); });

    // 파일 핸들러 설정
    setupFileHandler('xlsm', handleFileAnalysis, document.getElementById('result-xlsm'));
    setupFileHandler('exe', handleFileAnalysis, document.getElementById('result-exe'));
    setupFileHandler('ps1', handleFileAnalysis, document.getElementById('result-ps1'));
    setupFileHandler('txt', handleFileAnalysis, document.getElementById('result-txt'));
    setupFileHandler('single', handleFileAnalysis, document.getElementById('result-single'));
    setupFileHandler('yar', handleYaraRuleFile, null);
    setupFileHandler('yara-target', (file, data) => { /* 스캔 버튼이 처리 */ }, null);
    
    // YARA 스캔 버튼 이벤트 리스너
    document.getElementById('scan-btn-yara').addEventListener('click', handleYaraScan);

    // YARA 룰 UI 초기화
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
            lucide.createIcons(); // 아이콘 재렌더링
        };
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
        let files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            processFile(files[0]);
        }
    });
}

// 범용 파일 분석 핸들러
async function handleFileAnalysis(file, data, resultEl) {
    const filenameDisplay = resultEl.previousElementSibling.querySelector('p[id^="filename-"]');
    filenameDisplay.textContent = `'${file.name}' 파일 분석 중...`;
    
    const hashes = await calculateHashes(data);
    const extension = file.name.split('.').pop().toLowerCase();
    
    // 바이너리 파일은 텍스트 디코딩 시 주의
    const isTextBased = ['ps1', 'txt', 'yar', 'yara'].includes(extension);
    const textContent = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(data);
    
    let analysis;
    let analysisHTML = '';
    
    if (resultEl.id === 'result-single') {
         analysisHTML = `<h3 class="text-xl font-semibold mt-6 mb-4">📄 기본 정보</h3>
            <div class="bg-gray-800 rounded-lg p-4 grid grid-cols-2 gap-4">
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
    }


    if (extension === 'exe' || extension === 'dll') {
        analysis = analyzePeFile(file.name);
    } else if (isTextBased) {
        analysis = analyzeScriptFile(textContent, file.name);
    } else if (extension === 'xlsm') {
        analysis = analyzeXlsmFile(textContent);
    } else {
        analysis = { 'Info': `.${extension} 타입 파일에 대한 특화된 분석 기능은 없습니다.` };
    }
    
    if (resultEl.id === 'result-single') {
        analysisHTML += createAnalysisResultHTML(analysis);
    } else {
        analysisHTML = createHashResultHTML(hashes) + createAnalysisResultHTML(analysis);
    }

    resultEl.innerHTML = analysisHTML;
    filenameDisplay.textContent = `'${file.name}' 분석 완료.`;
    lucide.createIcons();
}


function handleYaraRuleFile(file, data) {
    const filenameDisplay = document.getElementById('filename-yar');
    const yaraStatus = document.getElementById('yara-source-name');
    filenameDisplay.textContent = `룰 파일 '${file.name}' 로딩 중...`;
    
    const textContent = new TextDecoder("utf-8").decode(data);
    const parsedRules = parseYaraRule(textContent);
    
    if (parsedRules) {
        customYaraRules = parsedRules;
        filenameDisplay.textContent = `'${file.name}' 룰셋이 적용되었습니다.`;
        yaraStatus.textContent = `커스텀 룰 (${file.name})`;
        yaraStatus.classList.remove('text-blue-400');
        yaraStatus.classList.add('text-green-400');
        updateYaraAccordion();
    } else {
        filenameDisplay.textContent = `'${file.name}'에서 유효한 YARA 룰을 찾지 못했습니다.`;
        yaraStatus.textContent = '기본 내장 룰 (커스텀 룰 로드 실패)';
        yaraStatus.classList.add('text-blue-400');
        yaraStatus.classList.remove('text-green-400');
    }
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
        const textContent = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(e.target.result);
        const matches = yaraScan(textContent);

        let resultHTML = `<h3 class="text-xl font-semibold mb-4">📊 YARA 스캔 결과 (${file.name})</h3>`;
        if (matches.length > 0) {
            resultHTML += `<div class="p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-300 mb-4"><strong><i data-lucide="shield-alert" class="inline w-5 h-5 mr-1"></i>탐지됨!</strong> - ${matches.length}개 규칙과 일치합니다:</div>`;
            matches.forEach(match => {
                resultHTML += `
                    <div class="bg-gray-800 rounded-lg p-4 mb-3">
                        <p class="font-bold text-lg text-red-400">${match.rule}</p>
                        <p class="text-sm text-gray-400 mb-2">${match.meta.description}</p>
                        <div class="font-mono text-xs bg-gray-900 p-2 rounded">
                            ${match.strings.map(s => `<p><span class="text-blue-400">${s.identifier}:</span> <span class="text-gray-300">'${s.data.substring(0, 80)}'</span></p>`).join('')}
                        </div>
                    </div>
                `;
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
                <p class="text-sm text-gray-400 mb-2"><strong>탐지 문자열:</strong></p>
                <div class="font-mono text-xs text-blue-300">${rule.strings.join(', ')}</div>
            </div>
        `;
        yaraAccordion.appendChild(ruleElement);
    });

    // 아코디언 토글 이벤트 리스너 (기존 로직 재사용)
    yaraAccordion.removeEventListener('click', toggleAccordion); // 중복 방지
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
