const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const cl = require('@polarsignals/custom-labels');
const { Worker } = require('worker_threads');

const PORT = process.env.PORT || 80;
const WORKER_COUNT = 8;

const begin = Date.now();

function mysleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function myrand(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const workers = [];
let currentWorker = 0;
const pendingRequests = new Map();
let requestIdCounter = 0;

for (let i = 0; i < WORKER_COUNT; i++) {
  const worker = new Worker(path.join(__dirname, 'worker.js'), {
    workerData: { workerId: i }
  });
  
  worker.on('message', ({ requestId, success, html, error }) => {
    const { res } = pendingRequests.get(requestId);
    pendingRequests.delete(requestId);
    
    if (success) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end(`<h1>Error: ${error}</h1>`);
    }    
  });
  
  worker.on('error', (error) => {
    console.error('Worker error:', error);
  });
  
  workers.push(worker);
}

function generateRandomString() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 10; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function processWithWorker(filePath, res, randomLabels) {
  const requestId = ++requestIdCounter;
  pendingRequests.set(requestId, { res });
  
  const worker = workers[currentWorker];
  currentWorker = (currentWorker + 1) % WORKER_COUNT;
  worker.postMessage({ filePath, requestId, randomLabels });
}

function startServer() {
  const server = http.createServer((req, res) => {
      const filePath = path.join(__dirname, req.url);
      
      const randomLabels = {};
      for (let i = 1; i <= 7; i++) {
        randomLabels[`r${i}`] = generateRandomString();
      }
      
      const labelArgs = Array.from({length: 7}, (_, i) => [`r${i+1}`, randomLabels[`r${i+1}`]]).flat();
      
      cl.withLabels(() => {
          processWithWorker(filePath, res, randomLabels);
      }, "filePath", filePath, ...labelArgs);
  });

  server.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}/`);
  });
}

startServer();
