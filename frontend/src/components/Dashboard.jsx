import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { filesAPI, searchAPI, authAPI } from '../services/api';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const [file, setFile] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [apiKeys, setApiKeys] = useState([]);
  const [newApiKeyName, setNewApiKeyName] = useState('');

  useEffect(() => {
    loadApiKeys();
  }, []);

  const loadApiKeys = async () => {
    try {
      const response = await authAPI.listApiKeys();
      setApiKeys(response.data);
    } catch (error) {
      console.error('Failed to load API keys:', error);
    }
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    setLoading(true);
    try {
      const response = await filesAPI.uploadFile(file);
      setUploadResult(response.data);
    } catch (error) {
      console.error('Upload failed:', error);
      setUploadResult({ error: 'Upload failed' });
    } finally {
      setLoading(false);
    }
  };

  const handleMultiEngineUpload = async () => {
    if (!file) return;

    setLoading(true);
    try {
      const response = await filesAPI.uploadFileMultiEngine(file);
      setUploadResult(response.data);
    } catch (error) {
      console.error('Multi-engine upload failed:', error);
      setUploadResult({ error: 'Multi-engine upload failed' });
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchQuery) return;

    setLoading(true);
    try {
      const response = await searchAPI.search(searchQuery);
      setSearchResults(response.data);
    } catch (error) {
      console.error('Search failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const createApiKey = async (e) => {
    e.preventDefault();
    if (!newApiKeyName) return;

    try {
      await authAPI.createApiKey({ name: newApiKeyName });
      setNewApiKeyName('');
      loadApiKeys();
    } catch (error) {
      console.error('Failed to create API key:', error);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-bold text-gray-900">VirusJaeger Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-700">
                Welcome, {user?.username}
                {user?.is_admin && (
                  <span className="ml-1 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                    Admin
                  </span>
                )}
              </span>
              <button
                onClick={logout}
                className="text-sm text-gray-500 hover:text-gray-700"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* File Upload Section */}
            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900">
                  File Upload
                </h3>
                <div className="mt-4">
                  <form onSubmit={handleFileUpload}>
                    <div className="flex items-center justify-center w-full">
                      <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-gray-300 border-dashed rounded-lg cursor-pointer bg-gray-50 hover:bg-gray-100">
                        <div className="flex flex-col items-center justify-center pt-5 pb-6">
                          <p className="mb-2 text-sm text-gray-500">
                            <span className="font-semibold">Click to upload</span> or drag and drop
                          </p>
                          <p className="text-xs text-gray-500">
                            {file ? file.name : 'Any file type'}
                          </p>
                        </div>
                        <input
                          type="file"
                          className="hidden"
                          onChange={(e) => setFile(e.target.files[0])}
                        />
                      </label>
                    </div>
                    
                    <div className="mt-4 flex space-x-3">
                      <button
                        type="submit"
                        disabled={!file || loading}
                        className="flex-1 bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50"
                      >
                        {loading ? 'Uploading...' : 'Quick Scan'}
                      </button>
                      <button
                        type="button"
                        onClick={handleMultiEngineUpload}
                        disabled={!file || loading}
                        className="flex-1 bg-purple-600 text-white px-4 py-2 rounded-md hover:bg-purple-700 disabled:opacity-50"
                      >
                        Multi-Engine Scan
                      </button>
                    </div>
                  </form>
                  
                  {uploadResult && (
                    <div className="mt-4 p-4 bg-gray-100 rounded-md">
                      <pre className="text-sm overflow-x-auto">
                        {JSON.stringify(uploadResult, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Search Section */}
            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900">
                  Search Files
                </h3>
                <div className="mt-4">
                  <form onSubmit={handleSearch}>
                    <div className="flex">
                      <input
                        type="text"
                        placeholder="Search by filename or hash..."
                        className="flex-1 border border-gray-300 rounded-l-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                      />
                      <button
                        type="submit"
                        disabled={loading}
                        className="bg-indigo-600 text-white px-4 py-2 rounded-r-md hover:bg-indigo-700 disabled:opacity-50"
                      >
                        Search
                      </button>
                    </div>
                  </form>
                  
                  {searchResults.length > 0 && (
                    <div className="mt-4 space-y-2">
                      {searchResults.map((result, index) => (
                        <div key={index} className="p-3 bg-gray-100 rounded-md">
                          <div className="text-sm font-medium">{result.filename}</div>
                          <div className="text-xs text-gray-600">{result.sha256}</div>
                          <div className="text-xs text-gray-500">Status: {result.status}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* API Keys Section */}
            <div className="bg-white overflow-hidden shadow rounded-lg lg:col-span-2">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900">
                  API Keys
                </h3>
                <div className="mt-4">
                  <form onSubmit={createApiKey} className="flex space-x-3 mb-4">
                    <input
                      type="text"
                      placeholder="API key name..."
                      className="flex-1 border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                      value={newApiKeyName}
                      onChange={(e) => setNewApiKeyName(e.target.value)}
                    />
                    <button
                      type="submit"
                      className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700"
                    >
                      Create Key
                    </button>
                  </form>
                  
                  <div className="space-y-2">
                    {apiKeys.map((key) => (
                      <div key={key.id} className="p-3 bg-gray-100 rounded-md">
                        <div className="flex justify-between items-start">
                          <div>
                            <div className="font-medium">{key.name}</div>
                            <div className="text-sm text-gray-600 font-mono">{key.key}</div>
                            <div className="text-xs text-gray-500">
                              Created: {new Date(key.created_at).toLocaleDateString()}
                            </div>
                          </div>
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            key.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                          }`}>
                            {key.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;