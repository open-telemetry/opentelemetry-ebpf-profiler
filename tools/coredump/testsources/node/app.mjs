function fib(n) {
  if (n < 2) {
     return n;
  }
  let a = fib(n - 1);
  let b = fib(n - 2);
  let rv = a + b;
  return rv;
}

function cpuBurn() {
//  console.log("start");
  const x = fib(42);
//  console.log(x);
  setTimeout(cpuBurn, 50);
}

cpuBurn();
setInterval(() => {}, 1000); // keep event loop alive