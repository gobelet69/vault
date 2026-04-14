import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.jsx";
import "./styles.css";

const rootElement = document.getElementById("vault-root");
if (!rootElement) {
  throw new Error("Missing #vault-root mount node.");
}

const root = createRoot(rootElement);
root.render(<App />);

