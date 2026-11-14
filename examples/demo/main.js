// A deliberately small, self-owned release fixture. No external services.
function calculateTotal(prices) {
  return Math.round(prices.reduce((sum, price) => sum + price, 0) * 0.9 * 100) / 100;
}
console.log(JSON.stringify({ total: calculateTotal([5, 10]) }));
//# sourceMappingURL=main.js.map
