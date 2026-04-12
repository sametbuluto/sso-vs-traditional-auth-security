const fs = require('fs');
const path = require('path');

class MetricsCollector {
  constructor(testId, testName, relatedPaper) {
    this.data = {
      testId,
      testName,
      relatedPaper,
      timestamp: new Date().toISOString(),
      environment: {
        secureMode: process.env.SECURE_MODE === 'true'
      },
      results: [],
      paperComparison: {}
    };
  }

  addResult(result) {
    this.data.results.push(result);
  }

  setComparison(paperResult, ourResult, alignment) {
    this.data.paperComparison = { paperResult, ourResult, alignment };
  }

  save() {
    const filename = `${this.data.testId.toLowerCase()}_${this.data.environment.secureMode ? 'secure' : 'insecure'}.json`;
    const resultsDir = path.join(__dirname, '..', 'results');
    
    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }
    
    const filePath = path.join(resultsDir, filename);
    fs.writeFileSync(filePath, JSON.stringify(this.data, null, 2));
    console.log(`[Metrics] Saved results to ${filename}`);
  }
}

module.exports = MetricsCollector;
