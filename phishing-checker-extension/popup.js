document.getElementById("checkBtn").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const url = tabs[0].url;
    const resultBox = document.getElementById("resultBox");
    const scoreContainer = document.getElementById("scoreContainer");
    const scoreBar = document.getElementById("scoreBar");

    try {
      const res = await fetch("http://localhost:5000/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
      });

      const data = await res.json();
      const score = data.score;
      const prediction = data.prediction;

      // Set result text
      const isPhishing = prediction === 1;
      resultBox.innerText = `Phishing score: ${score} → ${isPhishing ? "⚠️ Phishing" : "✅ Legitimate"}`;

      // Update bar width
      const scorePercent = score * 100;
      scoreBar.style.width = `${scorePercent}%`;

      // Set bar color (green to red based on score)
      if (score < 0.3) {
        scoreBar.style.backgroundColor = "#4CAF50"; // green
      } else if (score < 0.7) {
        scoreBar.style.backgroundColor = "#FFC107"; // yellow
      } else {
        scoreBar.style.backgroundColor = "#f44336"; // red
      }

      scoreContainer.style.display = "block";

      // Set style and show box
      resultBox.className = isPhishing ? "phishing" : "legit";
      resultBox.style.display = "block";
    } catch (error) {
      resultBox.innerText = "Error: Cannot reach backend.";
      resultBox.style.backgroundColor = "#999";
      resultBox.style.display = "block";
      scoreContainer.style.display = "none";
    }
  });
});
