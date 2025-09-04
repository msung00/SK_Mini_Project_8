# 🛡️ 악성코드 통합 분석 대시보드

> **교육 및 훈련용 보안 분석 도구**  
> 엑셀 매크로, 실행 파일, 파워쉘 스크립트, 로그 텍스트 등을 업로드하여  
> **종합 시나리오 분석 / 개별 파일 상세 분석 / YARA 룰 기반 스캔**을 수행할 수 있습니다.

---

## 🚀 주요 기능

### 📈 종합 시나리오 분석
- **1단계: 초기 침투 (Excel .xlsm)** → 매크로 키워드 탐지  
- **2단계: 악성 페이로드 실행 (Executable .exe/.dll)** → PE 헤더 및 의심 API 탐지  
- **3단계: 정보 수집 및 유출 (PowerShell .ps1 / Log .txt)** → 위험 키워드 및 예상 악성 행위 식별

### 📂 개별 파일 상세 분석
- 단일 파일 업로드 후 **MD5 / SHA1 / SHA256 해시 자동 계산**
- 악성 행위 예상 결과를 시각적으로 제공
- **PDF 보고서 생성 버튼** 지원

### 🚨 YARA 룰 관리 및 스캔
- **기본 내장 룰셋** + **사용자 정의(.yar) 룰 추가 가능**
- 드래그앤드롭으로 파일 업로드 후 YARA 스캔 수행
- 탐지 결과를 직관적인 UI로 표시

---




## 🛠️ 기술 스택

<p align="center">
  <!-- HTML -->
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white"/>
  <!-- CSS -->
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white"/>
  <!-- JavaScript -->
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black"/>
  <!-- TailwindCSS -->
  <img src="https://img.shields.io/badge/TailwindCSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white"/>

---

## 📂 프로젝트 구조

```bash
📦 project-root
├── index.html      # 메인 페이지 (UI 구조)
├── script.js       # 파일 분석 로직 & 이벤트 핸들러
├── style.css       # 사용자 정의 스타일
