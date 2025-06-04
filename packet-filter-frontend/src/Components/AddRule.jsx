import { useState, useEffect } from "react";
import axios from "axios";
const BASE_URL = import.meta.env.VITE_BASE_URL;

const AddRule = () => {
  const [rules, setRules] = useState([]);
  const [ruleName, setRuleName] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  // Fetch all rules on component mount
  useEffect(() => {
    const fetchRules = async () => {
      try {
        const response = await axios.get(`${BASE_URL}/api/rules/all`);
        console.log("Fetched rules:", response.data);
        setRules(response.data);
      } catch (error) {
        console.error("Error fetching rules:", error);
      }
    };
    fetchRules();
    }, []);

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!ruleName.trim()) return;

    try {
      const response = await axios.post(`${BASE_URL}/api/rules/create`, {
        rule_name: ruleName,
      });

      const newRule = response.data;
      setRules((prevRules) => [...prevRules, newRule]);
      setRuleName("");
    } catch (error) {
      console.error("Error creating rule:", error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 p-6 bg-gray-100 min-h-screen">
      <div className="bg-white border p-6 rounded-lg shadow-lg">
        <h1 className="text-2xl font-bold mb-4 text-gray-800">Rules</h1>
        <ul className="space-y-2">
          {rules.map((rule) => (
            <li
              key={rule.rule_id}
              className="p-3 bg-gray-50 border rounded-lg shadow-sm text-gray-700"
            >
              <span className="font-semibold italic">Rule ID:</span>{" "}
              {rule.rule_id}
              <br />
              {rule.rule_name}
            </li>
          ))}
        </ul>
      </div>

      <div className="bg-white border p-6 rounded-lg shadow-lg">
        <h2 className="text-xl font-semibold mb-4 text-gray-800">Add Rule</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="text"
            value={ruleName}
            onChange={(e) => setRuleName(e.target.value)}
            placeholder="Enter rule name"
            className="w-full p-3 border rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <button
            type="submit"
            className={`w-full py-3 rounded-lg font-semibold text-white transition duration-300 ${
              isLoading
                ? "bg-blue-300 cursor-not-allowed"
                : "bg-blue-500 hover:bg-blue-600"
            }`}
            disabled={isLoading}
          >
            {isLoading ? "Adding Rule..." : "Add Rule"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default AddRule;
