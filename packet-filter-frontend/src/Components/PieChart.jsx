import React, { useEffect, useState } from "react";
import { Pie } from "react-chartjs-2";
import axios from "axios";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import LoadingSpinner from "./LoadingSpinner";
const BASE_URL = import.meta.env.VITE_BASE_URL;;
ChartJS.register(ArcElement, Tooltip, Legend);

const PieChart = () => {
  const [chartData, setChartData] = useState(null);

  useEffect(() => {
    // Fetch data from the API
    const fetchData = async () => {
      try {
        const response = await axios.get(
          `${BASE_URL}/api/network/total-bytes-hostname` // Updated API endpoint
        );
        const data = response.data;

        // Transform the data for the pie chart
        const labels = data.map((item) => item.hostname);
        const values = data.map(
          (item) => item.total_downloaded + item.total_uploaded
        ); // Sum of downloaded and uploaded

        setChartData({
          labels,
          datasets: [
            {
              label: "Total Data Usage (Bytes)",
              data: values,
              backgroundColor: [
                "#FF6384",
                "#36A2EB",
                "#FFCE56",
                "#4BC0C0",
                "#9966FF",
                "#FF9F40",
              ],
              hoverBackgroundColor: [
                "#FF6384",
                "#36A2EB",
                "#FFCE56",
                "#4BC0C0",
                "#9966FF",
                "#FF9F40",
              ],
            },
          ],
        });
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
  }, []);

  return (
    <div className="w-full max-w-md mx-auto mt-8">
      <h2 className="text-center text-xl font-bold mb-4">
        Total Data Usage by Hostname
      </h2>
      {chartData ? <Pie data={chartData} /> : <LoadingSpinner />}
    </div>
  );
};

export default PieChart;
