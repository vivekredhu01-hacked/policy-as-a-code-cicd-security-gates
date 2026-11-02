function renderUserMessage(userInput) {
  // Controlled F02 fixture: Semgrep must flag this unsafe source pattern.
  return eval(userInput);
}

module.exports = { renderUserMessage };
