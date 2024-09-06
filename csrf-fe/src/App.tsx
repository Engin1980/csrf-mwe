import React from "react";
import logo from "./logo.svg";
import "./App.css";
import axios from "axios";

function App() {
  axios.defaults.baseURL = "http://localhost:5555";
  axios.defaults.withCredentials = true;
  axios.interceptors.request.use((c) => {
    const csrf: string | null = localStorage.getItem("csrf");
    if (csrf) {
      console.log("inter.req setting csrf " + csrf);
      c.headers["XSRF-TOKEN"] = csrf;
      c.headers["X-CSRF-TOKEN"] = csrf;
    }
    return c;
  });

  const getClick = () => {
    axios
      .get("")
      .then((q) => {
        console.log("GET completed");
        console.log("Cookies: " + document.cookie);
        const csrf = document.cookie
          .split(";")
          .filter((q) => q.startsWith("XSRF-TOKEN"))?.[0]
          ?.split("=")?.[1];
        console.log("CSRF token: " + csrf);
        if (csrf) localStorage.setItem("csrf", csrf);
      })
      .catch((e) => {
        console.error("GET failed");
        console.error(e);
      });
  };

  const postClick = () => {
    axios.post("").then((q) => {
      console.log("POST completed");
    });
  };

  return (
    <div className="App">
      <h1>CSRF test</h1>
      <input type="button" value="GET" onClick={getClick} />
      <input type="button" value="POST" onClick={postClick} />
    </div>
  );
}

export default App;
