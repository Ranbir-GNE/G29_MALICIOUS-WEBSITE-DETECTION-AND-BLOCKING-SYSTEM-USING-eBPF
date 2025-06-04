import { useState, useEffect } from "react";
import axios from "axios";
const BASE_URL = import.meta.env.VITE_BASE_URL;

const AssignDomains = () => {
  const [rules, setRules] = useState([]);
  const [selectedRule, setSelectedRule] = useState(null);
  const [domainName, setDomainName] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [domains, setDomains] = useState([]);

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

  useEffect(() => {
    const fetchDomains = async () => {
      if (!selectedRule) {
        setDomains([]); // Clear domains if no rule is selected
        return;
      }

      try {
        const response = await axios.get(
          `${BASE_URL}/api/blocked-domains/get/${selectedRule.rule_id}`
        );
        // Set domains directly from response data
        setDomains(response.data);
      } catch (error) {
        console.error("Error fetching domains:", error);
        setDomains([]);
      }
    };

    fetchDomains();
  }, [selectedRule]);

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!domainName.trim() || !selectedRule) return;

    setIsLoading(true);
    try {
      // Add domain
      await axios.post(
        `${BASE_URL}/api/blocked-domains/add/${selectedRule.rule_id}`,
        {
          domain: domainName,
        }
      );

      // Fetch updated domains list
      const response = await axios.get(
        `${BASE_URL}/api/blocked-domains/get/${selectedRule.rule_id}`
      );

      setDomains(response.data);
      setDomainName("");
    } catch (error) {
      console.error("Error adding domain:", error);
      alert("Failed to add domain. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleRuleClick = (rule) => {
    setSelectedRule(rule);
    setDomainName(""); // Clear domain input when switching rules
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 p-8 bg-gray-100 min-h-screen">
      {/* Rules Section */}
      <div className="lg:col-span-1 bg-white border p-6 rounded-lg shadow-lg">
        <h1 className="text-2xl font-bold mb-6 text-gray-800">Rules</h1>
        <ul className="space-y-4">
          {rules.map((rule) => (
            <li
              key={rule.rule_id}
              className={`p-4 border rounded-lg shadow-sm cursor-pointer transition-colors duration-200 ${
                selectedRule?.rule_id === rule.rule_id
                  ? "bg-blue-100 border-blue-300"
                  : "bg-gray-50 hover:bg-gray-100"
              }`}
              onClick={() => handleRuleClick(rule)}
            >
              <span className="font-semibold italic">Rule ID:</span>{" "}
              {rule.rule_id}
              <br />
              {rule.rule_name}
            </li>
          ))}
        </ul>
      </div>

      {/* Domains Section */}
      <div className="lg:col-span-2 bg-white border p-6 rounded-lg shadow-lg">
        <h2 className="text-xl font-semibold mb-6 text-gray-800">
          {selectedRule
            ? `Domains for ${selectedRule.rule_name}`
            : "Select a rule"}
        </h2>

        {selectedRule && (
          <div className="grid grid-cols-1 md:grid-cols-1 gap-6">
            {/* Existing Domains */}
            <div className="bg-gray-50 p-4 rounded-lg shadow-inner max-h-60 overflow-y-auto">
              <h3 className="text-lg font-medium mb-4">Existing Domains</h3>
              {domains.length > 0 ? (
                <ul className="space-y-2">
                  {domains.map((domain, index) => (
                    <li
                      key={index}
                      className="p-3 bg-white border rounded shadow-sm"
                    >
                      {domain.domain || domain}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-red-500 italic">No Domains Available</p>
              )}
            </div>

            {/* Add Domain Form */}
            <form
              onSubmit={handleSubmit}
              className="bg-gray-50 p-4 rounded-lg shadow-inner space-y-4"
            >
              <h3 className="text-lg font-medium mb-4">Add a New Domain</h3>
              <input
                type="text"
                value={domainName}
                onChange={(e) => setDomainName(e.target.value)}
                placeholder="Enter domain name"
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
                {isLoading ? "Adding Domain..." : "Add Domain"}
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};

export default AssignDomains;
