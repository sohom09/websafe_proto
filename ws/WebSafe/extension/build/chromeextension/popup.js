class WebSafeUI {
  constructor() {
    this.autoAnalyzeToggle = document.getElementById('autoAnalyzeToggle');
    this.urlInput = document.getElementById('urlInput');
    this.analyzeBtn = document.getElementById('analyzeBtn');
    this.pasteBtn = document.getElementById('pasteBtn');
    this.themeToggle = document.getElementById('themeToggle');
    this.resultsSection = document.getElementById('resultsSection');
    this.scoreValue = document.getElementById('scoreValue');
    this.progressFill = document.getElementById('progressFill');
    this.parametersList = document.getElementById('parametersList');
    this.loader = document.getElementById('loader');
    this.copyUrlBtn = document.getElementById('copyUrlBtn');
    this.init();
  }

  init() {
    document.body.classList.add('popup-collapsed');
    this.setupEventListeners();
    this.loadTheme();
    this.loadAutoAnalyzeSetting();
    this.checkAutoScanStatus();
    this.autoFillURL();
  }

  setupEventListeners() {
    this.analyzeBtn.addEventListener('click', () => this.handleAnalyze());
    this.pasteBtn.addEventListener('click', () => this.handlePaste());
    this.themeToggle.addEventListener('click', () => this.toggleTheme());
    this.urlInput.addEventListener('input', () => this.validateInput());
    if (this.copyUrlBtn) {
      this.copyUrlBtn.addEventListener('click', () => this.copyCurrentTabURL());
    }
    if (this.autoAnalyzeToggle) {
      this.autoAnalyzeToggle.addEventListener('change', () => {
        const isEnabled = this.autoAnalyzeToggle.checked;
        chrome.storage.sync.set({ autoAnalyze: isEnabled });
      });
    }
  }

  async handleAnalyze() {
    const url = this.urlInput.value.trim();
    if (!url) {
      this.showError('Please enter a URL');
      return;
    }

    try {
      this.showLoading(true);
      const analysis = await this.performAnalysis(url);
      console.log("Backend response:", analysis); // ← helpful for debugging
      this.displayResults(analysis);
      this.expandPopup();
    } catch (error) {
      this.showError(error.message || 'Analysis failed. Please try again.');
      console.error('Analysis error:', error);
    } finally {
      this.showLoading(false);
    }
  }

  async performAnalysis(url) {
    try {
      const response = await fetch('http://127.0.0.1:5000/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });
      if (!response.ok) {
        const text = await response.text();
        let errorMsg = `HTTP error ${response.status}`;
        try {
          const errData = JSON.parse(text);
          if (errData.error) errorMsg = errData.error;
        } catch (e) { }
        throw new Error(errorMsg);
      }
      return await response.json();
    } catch (error) {
      console.error('API call failed:', error);
      throw error;
    }
  }

  async handlePaste() {
    try {
      const text = await navigator.clipboard.readText();
      this.urlInput.value = text;
      this.validateInput();
    } catch (error) {
      this.showError('Failed to paste from clipboard');
    }
  }

  validateInput() {
    const url = this.urlInput.value.trim();
    const isValid = url && /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w- ./?%&=]*)?$/.test(url);
    this.analyzeBtn.disabled = !isValid;
  }

  displayResults(analysis) {
    this.resultsSection.classList.remove('hidden');

    // Backend sends score in 0–10 range → we use it directly
    const score = Number(analysis.score);                  // keep decimal if present
    const displayScore = score.toFixed(1);                 // format to exact decimal
    this.scoreValue.textContent = `${displayScore}/10`;

    // Progress bar: convert 0–10 → 0–100%
    const percentage = score * 10;
    this.progressFill.style.width = `${percentage}%`;

    // Optional: color the score based on value
    const scoreContainer = this.scoreValue.closest('.security-score') || this.scoreValue;
    scoreContainer.classList.remove('dangerous', 'warning', 'safe');
    if (score <= 3) {
      scoreContainer.classList.add('dangerous');
    } else if (score <= 6) {
      scoreContainer.classList.add('warning');
    } else {
      scoreContainer.classList.add('safe');
    }

    this.parametersList.innerHTML = '';
    analysis.parameters.forEach(param => {
      const paramElement = document.createElement('div');
      paramElement.className = 'parameter-item';
      paramElement.innerHTML = `
        <div class="parameter-name">
          <span>${param.icon}</span>
          <span>${param.name}</span>
        </div>
        <span class="parameter-status status-${param.status}">
          ${param.status.charAt(0).toUpperCase() + param.status.slice(1)}
        </span>
      `;
      this.parametersList.appendChild(paramElement);
    });
  }

  showError(message) {
    alert(message); // Consider replacing with a nicer UI element later
  }

  showLoading(isLoading) {
    if (isLoading) {
      this.analyzeBtn.disabled = true;
      this.analyzeBtn.querySelector('.btn-text').classList.add('hidden');
      this.loader.classList.remove('hidden');
    } else {
      this.analyzeBtn.disabled = false;
      this.analyzeBtn.querySelector('.btn-text').classList.remove('hidden');
      this.loader.classList.add('hidden');
    }
  }

  toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', newTheme);
    this.themeToggle.querySelector('.theme-icon').textContent = newTheme === 'light' ? '🌙' : '☀️';
    chrome.storage.sync.set({ theme: newTheme });
  }

  loadTheme() {
    chrome.storage.sync.get(['theme'], (result) => {
      const theme = result.theme || 'light';
      document.documentElement.setAttribute('data-theme', theme);
      this.themeToggle.querySelector('.theme-icon').textContent = theme === 'light' ? '🌙' : '☀️';
    });
  }

  checkAutoScanStatus() {
    chrome.storage.sync.get(['autoScan'], (result) => {
      const autoScan = result.autoScan !== false;
      const statusDot = document.querySelector('.status-dot');
      if (statusDot) {
        if (autoScan) statusDot.classList.add('active');
        else statusDot.classList.remove('active');
      }
    });
  }

  expandPopup() {
    document.body.classList.remove('popup-collapsed');
    document.body.classList.add('popup-expanded');
  }

  async copyCurrentTabURL() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        await navigator.clipboard.writeText(tab.url);
        this.urlInput.value = tab.url;
        this.validateInput();
        alert("URL copied: " + tab.url);
      } else {
        alert("Could not fetch tab URL");
      }
    } catch (error) {
      alert("Failed to copy URL: " + error);
    }
  }

  async autoFillURL() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        this.urlInput.value = tab.url;
        this.validateInput();

        chrome.storage.sync.get(['autoAnalyze'], (result) => {
          const isEnabled = result.autoAnalyze !== false;
          if (isEnabled && this.urlInput.value.trim()) {
            setTimeout(() => {
              this.handleAnalyze();
            }, 500);
          }
        });
      }
    } catch (e) {
      console.error('Failed to auto-fill or analyze URL:', e);
    }
  }

  loadAutoAnalyzeSetting() {
    chrome.storage.sync.get(['autoAnalyze'], (result) => {
      const isEnabled = result.autoAnalyze !== false;
      if (this.autoAnalyzeToggle) {
        this.autoAnalyzeToggle.checked = isEnabled;
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  new WebSafeUI();
});