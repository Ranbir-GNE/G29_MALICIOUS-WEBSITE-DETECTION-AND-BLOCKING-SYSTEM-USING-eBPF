import { useEffect, useState } from "react";
import axios from "axios";
import { format } from "date-fns";
const BASE_URL = import.meta.env.VITE_BASE_URL;

const CumalativeTable = () => {
  const [data, setData] = useState([]);
  const [filteredData, setFilteredData] = useState([]);
  const [filter, setFilter] = useState("");
  const [hostnameFilter, setHostnameFilter] = useState("");
  const [dateFilter, setDateFilter] = useState("");
  const [sortConfig, setSortConfig] = useState({ key: null, direction: null });

  useEffect(() => {
    // Fetch data from the API
    const fetchData = async () => {
      try {
        const response = await axios.get(
          `${BASE_URL}/api/network/bytes-usage/`
        ); // API endpoint
        console.log("Fetched data:", response.data);
        setData(response.data);
        setFilteredData(response.data);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
  }, []);

  useEffect(() => {
    // Filter data based on the filter inputs
    const filtered = data.filter((row) => {
      const matchesSourceIP = row.source_ip
        .toLowerCase()
        .includes(filter.toLowerCase());
      const matchesHostname = row.hostname
        .toLowerCase()
        .includes(hostnameFilter.toLowerCase());
      const matchesDate = dateFilter
        ? format(new Date(row.date), "yyyy-MM-dd") === dateFilter
        : true;

      return matchesSourceIP && matchesHostname && matchesDate;
    });
    setFilteredData(filtered);
  }, [filter, hostnameFilter, dateFilter, data]);

  const handleSort = (key) => {
    let direction = "ascending";
    if (sortConfig.key === key && sortConfig.direction === "ascending") {
      direction = "descending";
    }
    setSortConfig({ key, direction });

    const sortedData = [...filteredData].sort((a, b) => {
      if (a[key] < b[key]) return direction === "ascending" ? -1 : 1;
      if (a[key] > b[key]) return direction === "ascending" ? 1 : -1;
      return 0;
    });
    setFilteredData(sortedData);
  };

  return (
    <div className="w-full max-w-6xl mx-auto mt-8">
      <h2 className="text-center text-xl font-bold mb-4">
        Cumulative Data Usage
      </h2>
      <div className="mb-4 flex flex-wrap gap-4">
        <input
          type="text"
          placeholder="Filter by Source IP"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="border border-gray-300 px-4 py-2 flex-1"
        />
        <input
          type="text"
          placeholder="Filter by Hostname"
          value={hostnameFilter}
          onChange={(e) => setHostnameFilter(e.target.value)}
          className="border border-gray-300 px-4 py-2 flex-1"
        />
        <input
          type="date"
          value={dateFilter}
          onChange={(e) => setDateFilter(e.target.value)}
          className="border border-gray-300 px-4 py-2 flex-1"
        />
      </div>
      <table className="table-auto w-full border-collapse border border-gray-300">
        <thead>
          <tr className="bg-gray-100">
            <th
              className="border border-gray-300 px-4 py-2 cursor-pointer"
              onClick={() => handleSort("source_ip")}
            >
              Source IP
            </th>
            <th
              className="border border-gray-300 px-4 py-2 cursor-pointer"
              onClick={() => handleSort("hostname")}
            >
              Hostname
            </th>
            <th
              className="border border-gray-300 px-4 py-2 cursor-pointer"
              onClick={() => handleSort("downloaded")}
            >
              Downloaded (Bytes)
            </th>
            <th
              className="border border-gray-300 px-4 py-2 cursor-pointer"
              onClick={() => handleSort("uploaded")}
            >
              Uploaded (Bytes)
            </th>
            <th
              className="border border-gray-300 px-4 py-2 cursor-pointer"
              onClick={() => handleSort("date")}
            >
              Date
            </th>
          </tr>
        </thead>
        <tbody>
          {filteredData.length > 0 ? (
            filteredData.map((row, index) => (
              <tr key={index} className="text-center">
                <td className="border border-gray-300 px-4 py-2">
                  {row.source_ip}
                </td>
                <td className="border border-gray-300 px-4 py-2">
                  {row.hostname}
                </td>
                <td className="border border-gray-300 px-4 py-2">
                  {row.downloaded}
                </td>
                <td className="border border-gray-300 px-4 py-2">
                  {row.uploaded}
                </td>
                <td className="border border-gray-300 px-4 py-2">
                  {/* {format(new Date(row.date), "dd/MM/yyyy")} */}
                  {new Date(row.date).toLocaleDateString("en-GB", {
                    year: "numeric",
                    month: "2-digit",
                    day: "2-digit",
                  })}
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="5" className="text-center py-4">
                No Data Yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default CumalativeTable;
