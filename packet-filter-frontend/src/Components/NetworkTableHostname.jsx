import React, { useEffect, useState } from "react";
import axios from "axios";
const BASE_URL = import.meta.env.VITE_BASE_URL;;
const NetworkTableHostname = () => {
  const [data, setData] = useState([]);

  useEffect(() => {
    // Fetch data from the API
    const fetchData = async () => {
      try {
        const response = await axios.get(
          `${BASE_URL}/api/network/total-bytes-hostname`
        ); // Updated API endpoint
        setData(response.data); // Use the aggregated data directly
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
  }, []);

  return (
    <div className="w-full max-w-4xl mx-auto mt-8">
      <h2 className="text-center text-xl font-bold mb-4">
        Network Data Usage by Hostname
      </h2>
      <table className="table-auto w-full border-collapse border border-gray-300">
        <thead>
          <tr className="bg-gray-100">
            <th className="border border-gray-300 px-4 py-2">Hostname</th>
            <th className="border border-gray-300 px-4 py-2">
              Downloaded (Bytes)
            </th>
            <th className="border border-gray-300 px-4 py-2">
              Uploaded (Bytes)
            </th>
          </tr>
        </thead>
        <tbody>
          {data.length > 0 ? (
            data.map((row, index) => (
              <tr key={index} className="text-center">
                <td className="border border-gray-300 px-4 py-2">
                  {row.hostname}
                </td>
                <td className="border border-gray-300 px-4 py-2">
                  {row.total_downloaded}
                </td>
                <td className="border border-gray-300 px-4 py-2">
                  {row.total_uploaded}
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="3" className="text-center py-4">
                Loading...
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default NetworkTableHostname;
