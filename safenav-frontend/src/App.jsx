import React from "react";
import "./App.css";
import URLForm from "./components/URLForm";

function App() {
  return (
    <div className="app-container">
      <header>
        <h1>
          <svg className="logo" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          SafeNav
        </h1>
        <p className="tagline">Web Security Analysis</p>
      </header>
      
      <div className="form-container">
        <URLForm />
      </div>
    </div>
  );
}

export default App;