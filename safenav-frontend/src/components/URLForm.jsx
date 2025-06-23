import React, { useState } from "react";
import axios from "axios";
import ResultCard from "./ResultCard";

const URLForm = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post("http://localhost:8080/api/check", {
        url: url,
      });
      setResult(response.data);
    } catch (error) {
      alert("Error connecting to backend");
    }
    setLoading(false);
  };

  return (
    <div className="form-container">
      <form onSubmit={handleSubmit} className="form-content">
        <div className="input-group">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter website URL..."
            required
          />
          <button type="submit">Check Safety</button>
        </div>
      </form>

      {loading && <p style={{ marginTop: "1rem" }}>🔄 Checking URL...</p>}
      {result && <ResultCard result={result} />}
    </div>
  );
};

export default URLForm;
