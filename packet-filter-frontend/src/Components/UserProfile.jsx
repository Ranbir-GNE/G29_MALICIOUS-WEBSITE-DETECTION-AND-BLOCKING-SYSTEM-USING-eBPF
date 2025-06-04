import React, { useContext, useEffect, useState } from "react";
import axios from "axios";
import userContext from "../context/UserContext";
const BASE_URL = import.meta.env.VITE_BASE_URL;;
const UserProfile = () => {
  const [userData, setUserData] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const authContext = useContext(userContext);

  useEffect(() => {
    // Extract user ID from authContext
    const userId = authContext?.loginUser?.user?.id;

    if (!userId) {
      setErrorMessage("User ID not found. Please log in again.");
      setIsLoading(false);
      return;
    }

    // Fetch user data from the API
    const fetchUserData = async () => {
      try {
        const response = await axios.get(
          `${BASE_URL}/api/user/${userId}`
        );
        setUserData(response.data.user);
      } catch (error) {
        console.error("Error fetching user data:", error);
        setErrorMessage(
          error.response?.data?.message || "Failed to fetch user data."
        );
      } finally {
        setIsLoading(false);
      }
    };

    fetchUserData();
  }, [authContext]);

  if (isLoading) {
    return <div className="text-center mt-4">Loading user data...</div>;
  }

  if (errorMessage) {
    return <div className="text-center text-red-500 mt-4">{errorMessage}</div>;
  }

  return (
    <div className="w-full max-w-md mx-auto mt-8 bg-white p-4 rounded shadow">
      <h2 className="text-center text-xl font-bold mb-4">User Profile</h2>
      {userData && (
        <div>
          <p>
            <strong>ID:</strong> {userData.id}
          </p>
          <p>
            <strong>Username:</strong> {userData.username}
          </p>
          <p>
            <strong>Email:</strong> {userData.email}
          </p>
        </div>
      )}
    </div>
  );
};

export default UserProfile;
