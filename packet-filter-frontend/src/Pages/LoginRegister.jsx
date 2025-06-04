import React, { useContext, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import userContext from "../context/UserContext";

const CumalativeTable = () => {
  const [loginData, setLoginData] = useState({ email: "", password: "" });
  const [userData, setUserData] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const authContext = useContext(userContext);
  const navigate = useNavigate();
  const BASE_URL = process.env.BASE_URL;

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setLoginData((prev) => ({ ...prev, [name]: value }));
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage("");

    try {
      const response = await axios.post(`${BASE_URL}/api/login`, {
        email: loginData.email,
        password: loginData.password,
      });

      if (response.status === 200) {
        setUserData(response.data.user);
        authContext.setLoginUser(response.data);

        navigate("/dashboard");
      }
    } catch (error) {
      console.error("Error during login:", error);
      setErrorMessage(
        error.response?.data?.message || "Login failed. Please try again."
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md mx-auto mt-8">
      <h2 className="text-center text-xl font-bold mb-4">User Login</h2>

      {/* Login Form */}
      <form onSubmit={handleLogin} className="bg-white p-4 rounded shadow">
        <div className="mb-4">
          <label className="block mb-2 font-semibold">Email</label>
          <input
            type="email"
            name="email"
            value={loginData.email}
            onChange={handleInputChange}
            className="w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter your email"
            required
          />
        </div>
        <div className="mb-4">
          <label className="block mb-2 font-semibold">Password</label>
          <input
            type="password"
            name="password"
            value={loginData.password}
            onChange={handleInputChange}
            className="w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter your password"
            required
          />
        </div>
        <button
          type="submit"
          className="w-full bg-blue-500 text-white py-2 rounded-lg font-semibold hover:bg-blue-600 transition duration-300"
          disabled={isLoading}
        >
          {isLoading ? "Logging in..." : "Login"}
        </button>
      </form>

      {/* Error Message */}
      {errorMessage && (
        <div className="mt-4 text-red-500 text-center">{errorMessage}</div>
      )}

      {/* User Data */}
      {userData && (
        <div className="mt-8 bg-gray-100 p-4 rounded shadow">
          <h3 className="text-lg font-bold mb-2">User Details</h3>
          <p>
            <strong>ID:</strong> {userData.id}
          </p>
          <p>
            <strong>Email:</strong> {userData.email}
          </p>
          <p>
            <strong>Username:</strong> {userData.username}
          </p>
        </div>
      )}
    </div>
  );
};

export default CumalativeTable;
