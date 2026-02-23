/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Upload, 
  FileText, 
  Download, 
  Trash2, 
  User, 
  Shield, 
  LogOut, 
  Search,
  File,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Filter,
  LogIn,
  UserPlus,
  ChevronDown,
  FolderOpen,
  Eye,
  FileImage,
  FileJson,
  FileCode,
  FileVideo,
  FileAudio,
  FileArchive,
  FileSpreadsheet,
  FilePieChart
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface FileRecord {
  id: number;
  name: string;
  original_name: string;
  mime_type: string;
  size: number;
  category: string;
  expiry_date: string | null;
  upload_date: string;
}

interface UserInfo {
  email: string;
  isAdmin: boolean;
  role: string;
}

const CATEGORIES = ['Documents', 'Images', 'Reports', 'Presentations', 'Other'];

export default function App() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [files, setFiles] = useState<FileRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [authMode, setAuthMode] = useState<'login' | 'register' | 'none'>('none');
  const [uploadCategory, setUploadCategory] = useState('Documents');
  const [uploadExpiry, setUploadExpiry] = useState('');
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);
  const [isBulkDeleting, setIsBulkDeleting] = useState(false);
  const [showBulkConfirm, setShowBulkConfirm] = useState(false);
  
  // Auth Form State
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const sessionId = localStorage.getItem('sessionId');

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('/api/health');
        if (res.ok) {
          console.log('Server health check passed');
        } else {
          console.warn('Server health check failed:', res.status);
        }
      } catch (err) {
        console.error('Server is unreachable:', err);
        setError('Cannot connect to server. Please ensure the backend is running.');
      }
    };

    checkHealth();

    if (sessionId) {
      fetchUser();
    } else {
      setLoading(false);
    }
    fetchFiles();

    // Auto-refresh every 30 seconds to ensure visibility of new uploads
    const interval = setInterval(fetchFiles, 30000);
    return () => clearInterval(interval);
  }, [sessionId]);

  const fetchUser = async () => {
    try {
      const res = await fetch('/api/user', {
        headers: { 'x-session-id': sessionId || '' }
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data);
      } else {
        const errorText = await res.text();
        console.error('Failed to fetch user:', errorText);
        localStorage.removeItem('sessionId');
        setUser(null);
      }
    } catch (err) {
      console.error('User fetch network error:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchFiles = async () => {
    try {
      const res = await fetch('/api/files');
      if (res.ok) {
        const data = await res.json();
        console.log('Fetched files:', data);
        setFiles(data);
      } else {
        const errorText = await res.text();
        console.error('Failed to fetch files:', errorText);
        setError(`Server error: ${res.status}`);
      }
    } catch (err: any) {
      console.error('Failed to fetch files (Network Error):', err);
      setError(`Connection failed: ${err.message || 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLocalAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthLoading(true);
    setError(null);

    const endpoint = authMode === 'login' ? '/api/login' : '/api/register';
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();
      if (res.ok) {
        if (authMode === 'login') {
          localStorage.setItem('sessionId', data.sessionId);
          setUser({ email: data.email, isAdmin: data.role === 'admin', role: data.role });
          setAuthMode('none');
          setSuccess('Welcome back!');
        } else {
          setAuthMode('login');
          setSuccess('Registration successful! Please log in.');
        }
        setEmail('');
        setPassword('');
      } else {
        setError(data.error || 'Authentication failed');
      }
    } catch (err) {
      setError('Network error');
    } finally {
      setAuthLoading(false);
      setTimeout(() => setSuccess(null), 3000);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const res = await fetch('/api/auth/url');
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to get auth URL');
      }
      const { url } = await res.json();
      console.log('Received Google Auth URL:', url);
      
      const width = 600;
      const height = 700;
      const left = window.screenX + (window.outerWidth - width) / 2;
      const top = window.screenY + (window.outerHeight - height) / 2;
      
      const authWindow = window.open(
        url,
        'google_oauth',
        `width=${width},height=${height},left=${left},top=${top}`
      );

      if (!authWindow) {
        setError('Popup blocked! Please allow popups for this site.');
        return;
      }

      const handleMessage = (event: MessageEvent) => {
        if (event.data?.type === 'OAUTH_AUTH_SUCCESS') {
          localStorage.setItem('sessionId', event.data.sessionId);
          window.removeEventListener('message', handleMessage);
          fetchUser();
          setAuthMode('none');
          setSuccess('Successfully logged in with Google!');
          setTimeout(() => setSuccess(null), 3000);
        }
      };

      window.addEventListener('message', handleMessage);
    } catch (err) {
      setError('Failed to initiate Google login.');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('sessionId');
    setUser(null);
    setSuccess('Logged out successfully.');
    setTimeout(() => setSuccess(null), 3000);
  };

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setError(null);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('category', uploadCategory);
    if (uploadExpiry) {
      formData.append('expiry_date', new Date(uploadExpiry).toISOString());
    }

    const currentSessionId = localStorage.getItem('sessionId');
    try {
      const res = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'x-session-id': currentSessionId || '' },
        body: formData
      });

      if (res.ok) {
        setSuccess('File uploaded successfully!');
        fetchFiles();
        setUploadExpiry('');
        if (fileInputRef.current) fileInputRef.current.value = '';
        setTimeout(() => setSuccess(null), 3000);
      } else {
        const data = await res.json();
        setError(data.error || 'Upload failed');
      }
    } catch (err) {
      setError('Network error during upload');
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (id: number) => {
    console.log(`Executing delete for file ID: ${id}`);
    const currentSessionId = localStorage.getItem('sessionId');
    try {
      const res = await fetch(`/api/files/${id}`, {
        method: 'DELETE',
        headers: { 'x-session-id': currentSessionId || '' }
      });

      if (res.ok) {
        setSuccess('File deleted successfully');
        fetchFiles();
        setSelectedIds(prev => prev.filter(sid => sid !== id));
        setConfirmDeleteId(null);
        setTimeout(() => setSuccess(null), 3000);
      } else {
        const data = await res.json();
        setError(data.error || 'Failed to delete file');
      }
    } catch (err) {
      setError('Network error');
    }
  };

  const handleBulkDelete = async () => {
    if (selectedIds.length === 0) return;
    setIsBulkDeleting(true);
    
    const currentSessionId = localStorage.getItem('sessionId');
    try {
      const res = await fetch('/api/files', {
        method: 'DELETE',
        headers: { 
          'x-session-id': currentSessionId || '',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ids: selectedIds })
      });

      if (res.ok) {
        setSuccess(`${selectedIds.length} files deleted`);
        fetchFiles();
        setSelectedIds([]);
        setTimeout(() => setSuccess(null), 3000);
      } else {
        const data = await res.json();
        setError(data.error || 'Failed to delete files');
      }
    } catch (err) {
      setError('Network error');
    } finally {
      setIsBulkDeleting(false);
    }
  };

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => 
      prev.includes(id) ? prev.filter(sid => sid !== id) : [...prev, id]
    );
  };

  const selectAll = () => {
    if (selectedIds.length === filteredFiles.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredFiles.map(f => f.id));
    }
  };

  const [previewFile, setPreviewFile] = useState<FileRecord | null>(null);

  const handleDownload = (id: number, originalName: string) => {
    console.log(`Downloading file: ${originalName} (ID: ${id})`);
    // Direct window.open is often more reliable than hidden links in some sandboxed environments
    window.open(`/api/files/${id}/download`, '_blank');
    setSuccess('Download started');
    setTimeout(() => setSuccess(null), 2000);
  };

  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewContent, setPreviewContent] = useState<string | null>(null);

  useEffect(() => {
    if (previewFile) {
      if (previewFile.mime_type.startsWith('text/') || 
          previewFile.mime_type === 'application/javascript' || 
          previewFile.mime_type === 'application/json') {
        fetch(`/api/files/${previewFile.id}/preview`)
          .then(res => res.text())
          .then(text => setPreviewContent(text))
          .catch(() => setPreviewContent('Failed to load text content.'));
      } else if (previewFile.mime_type === 'application/pdf' || previewFile.mime_type.startsWith('image/')) {
        // Use Blob URL to bypass some Chrome iframe/object blocks
        fetch(`/api/files/${previewFile.id}/preview`)
          .then(res => res.blob())
          .then(blob => {
            const url = URL.createObjectURL(blob);
            setPreviewUrl(url);
          })
          .catch(() => setError('Failed to load preview.'));
      }
    } else {
      setPreviewContent(null);
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
        setPreviewUrl(null);
      }
    }
  }, [previewFile]);

  const getFileIcon = (mime: string, name: string) => {
    const m = mime.toLowerCase();
    const n = name.toLowerCase();
    
    if (m.startsWith('image/')) return <FileImage className="w-7 h-7 text-blue-500" />;
    if (m === 'application/pdf') return <FileText className="w-7 h-7 text-red-500" />;
    if (m.startsWith('video/')) return <FileVideo className="w-7 h-7 text-purple-500" />;
    if (m.startsWith('audio/')) return <FileAudio className="w-7 h-7 text-pink-500" />;
    if (m === 'application/json') return <FileJson className="w-7 h-7 text-yellow-600" />;
    if (m.includes('javascript') || n.endsWith('.js') || n.endsWith('.ts') || n.endsWith('.css')) return <FileCode className="w-7 h-7 text-emerald-500" />;
    if (m.includes('zip') || m.includes('archive') || m.includes('tar')) return <FileArchive className="w-7 h-7 text-orange-500" />;
    if (m.includes('sheet') || m.includes('excel') || n.endsWith('.csv')) return <FileSpreadsheet className="w-7 h-7 text-green-600" />;
    if (m.includes('presentation') || m.includes('powerpoint')) return <FilePieChart className="w-7 h-7 text-orange-600" />;
    
    return <FileText className="w-7 h-7 text-zinc-500" />;
  };

  const renderPreview = () => {
    if (!previewFile) return null;

    const mime = previewFile.mime_type.toLowerCase();
    const isImage = mime.startsWith('image/');
    const isPDF = mime === 'application/pdf';
    const isText = mime.startsWith('text/') || 
                   mime === 'application/javascript' || 
                   mime === 'application/json' || 
                   mime === 'application/xml' ||
                   previewFile.original_name.endsWith('.md') ||
                   previewFile.original_name.endsWith('.js') ||
                   previewFile.original_name.endsWith('.ts') ||
                   previewFile.original_name.endsWith('.css');

    return (
      <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={() => setPreviewFile(null)}
          className="absolute inset-0 bg-zinc-900/60 backdrop-blur-md"
        />
        <motion.div 
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.9, y: 20 }}
          className="relative bg-white w-full max-w-5xl h-[80vh] rounded-3xl shadow-2xl overflow-hidden flex flex-col"
        >
          <div className="p-4 border-b border-zinc-100 flex items-center justify-between bg-white">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-zinc-50 rounded-lg flex items-center justify-center">
                <FileText className="w-4 h-4 text-zinc-500" />
              </div>
              <div>
                <h3 className="font-bold text-sm truncate max-w-[200px] sm:max-w-md">{previewFile.original_name}</h3>
                <p className="text-[10px] text-zinc-400 uppercase font-bold tracking-wider">{previewFile.category} • {formatSize(previewFile.size)}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {user?.isAdmin && (
                <div className="relative">
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmDeleteId(confirmDeleteId === previewFile.id ? null : previewFile.id);
                    }}
                    className={`p-2 rounded-full transition-all ${
                      confirmDeleteId === previewFile.id 
                        ? 'bg-red-500 text-white shadow-lg' 
                        : 'hover:bg-red-50 text-red-500'
                    }`}
                    title="Delete File"
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                  
                  <AnimatePresence>
                    {confirmDeleteId === previewFile.id && (
                      <motion.div 
                        initial={{ opacity: 0, scale: 0.8, y: 10 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.8, y: 10 }}
                        className="absolute right-0 top-full mt-2 z-50 bg-white border border-zinc-200 shadow-2xl rounded-2xl p-4 w-48"
                      >
                        <p className="text-xs font-bold text-zinc-900 mb-3">Delete this file?</p>
                        <div className="flex gap-2">
                          <button 
                            onClick={(e) => {
                              e.stopPropagation();
                              setConfirmDeleteId(null);
                            }}
                            className="flex-1 py-1.5 text-[10px] font-bold uppercase tracking-wider text-zinc-500 hover:bg-zinc-50 rounded-lg transition-colors"
                          >
                            No
                          </button>
                          <button 
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDelete(previewFile.id);
                              setPreviewFile(null);
                            }}
                            className="flex-1 py-1.5 text-[10px] font-bold uppercase tracking-wider bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors"
                          >
                            Yes
                          </button>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              )}
              <button 
                onClick={() => handleDownload(previewFile.id, previewFile.original_name)}
                className="p-2 hover:bg-zinc-100 rounded-full transition-colors text-zinc-600"
                title="Download"
              >
                <Download className="w-5 h-5" />
              </button>
              <button 
                onClick={() => setPreviewFile(null)}
                className="p-2 hover:bg-zinc-100 rounded-full transition-colors text-zinc-600"
              >
                <LogOut className="w-5 h-5 rotate-90" />
              </button>
            </div>
          </div>
          
          <div className="flex-1 bg-zinc-50 overflow-auto flex items-center justify-center">
            {isImage && previewUrl ? (
              <div className="w-full h-full p-4 flex items-center justify-center">
                <img 
                  src={previewUrl} 
                  alt={previewFile.original_name}
                  className="max-w-full max-h-full object-contain rounded-lg shadow-2xl"
                />
              </div>
            ) : isPDF && previewUrl ? (
              <iframe 
                src={previewUrl} 
                className="w-full h-full border-none"
                title="PDF Preview"
              />
            ) : isText ? (
              <div className="w-full h-full bg-white overflow-auto">
                {previewContent !== null ? (
                  <pre className="p-8 font-mono text-sm whitespace-pre-wrap text-zinc-800 leading-relaxed selection:bg-zinc-200">
                    {previewContent}
                  </pre>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full gap-3">
                    <Loader2 className="w-8 h-8 animate-spin text-zinc-300" />
                    <p className="text-xs font-bold uppercase tracking-widest text-zinc-400">Loading Content...</p>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center p-12">
                <div className="w-24 h-24 bg-zinc-100 rounded-full flex items-center justify-center mx-auto mb-6">
                  <FolderOpen className="w-10 h-10 text-zinc-300" />
                </div>
                <h3 className="text-lg font-bold text-zinc-900 mb-2">Preview Unavailable</h3>
                <p className="text-zinc-500 text-sm max-w-xs mx-auto mb-8">
                  {previewFile.mime_type === 'application/pdf' || previewFile.mime_type.startsWith('image/') ? 'Loading preview...' : "We don't support direct previews for this file type yet. You can download it to view on your device."}
                </p>
                <button 
                  onClick={() => handleDownload(previewFile.id, previewFile.original_name)}
                  className="bg-zinc-900 text-white px-8 py-3 rounded-2xl font-bold hover:bg-zinc-800 transition-all active:scale-95 flex items-center gap-2 mx-auto"
                >
                  <Download className="w-5 h-5" />
                  Download File
                </button>
              </div>
            )}
          </div>
        </motion.div>
      </div>
    );
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const filteredFiles = files.filter(f => {
    const name = f.original_name || '';
    const category = f.category || 'Other';
    const matchesSearch = name.toLowerCase().includes(searchQuery.toLowerCase()) || 
                         category.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = selectedCategory === 'All' || category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-50 flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-zinc-400" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900 font-sans selection:bg-zinc-200">
      {/* Navigation */}
      <nav className="sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-zinc-200">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-zinc-900 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="font-semibold text-lg tracking-tight">SecureShare</span>
          </div>

          <div className="flex items-center gap-4">
            {user ? (
              <div className="flex items-center gap-3">
                <div className="hidden sm:flex flex-col items-end">
                  <span className="text-sm font-medium">{user.email}</span>
                  <span className="text-[10px] uppercase tracking-wider text-zinc-500 font-bold">
                    {user.isAdmin ? 'Administrator' : 'User'}
                  </span>
                </div>
                <button 
                  onClick={handleLogout}
                  className="p-2 hover:bg-zinc-100 rounded-full transition-colors text-zinc-600"
                  title="Logout"
                >
                  <LogOut className="w-5 h-5" />
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <button 
                  onClick={() => setAuthMode('login')}
                  className="text-sm font-medium text-zinc-600 hover:text-zinc-900 px-3 py-2"
                >
                  Log In
                </button>
                <button 
                  onClick={() => setAuthMode('register')}
                  className="bg-zinc-900 text-white px-4 py-2 rounded-full text-sm font-medium hover:bg-zinc-800 transition-all active:scale-95"
                >
                  Sign Up
                </button>
              </div>
            )}
          </div>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-4 py-8">
        {/* Auth Modal */}
        <AnimatePresence>
          {authMode !== 'none' && (
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                onClick={() => setAuthMode('none')}
                className="absolute inset-0 bg-zinc-900/40 backdrop-blur-sm"
              />
              <motion.div 
                initial={{ opacity: 0, scale: 0.95, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95, y: 20 }}
                className="relative bg-white w-full max-w-md rounded-3xl shadow-2xl p-8"
              >
                <div className="text-center mb-8">
                  <div className="w-12 h-12 bg-zinc-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    {authMode === 'login' ? <LogIn className="w-6 h-6" /> : <UserPlus className="w-6 h-6" />}
                  </div>
                  <h2 className="text-2xl font-bold">{authMode === 'login' ? 'Welcome Back' : 'Create Account'}</h2>
                  <p className="text-zinc-500 text-sm mt-1">
                    {authMode === 'login' ? 'Access your shared files' : 'Join SecureShare to access files'}
                  </p>
                </div>

                <form onSubmit={handleLocalAuth} className="space-y-4">
                  <div>
                    <label className="block text-xs font-bold uppercase tracking-wider text-zinc-500 mb-1.5 ml-1">Email Address</label>
                    <input 
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full px-4 py-3 bg-zinc-50 border border-zinc-200 rounded-2xl focus:outline-none focus:ring-2 focus:ring-zinc-900/5 transition-all"
                      placeholder="name@example.com"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-bold uppercase tracking-wider text-zinc-500 mb-1.5 ml-1">Password</label>
                    <input 
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full px-4 py-3 bg-zinc-50 border border-zinc-200 rounded-2xl focus:outline-none focus:ring-2 focus:ring-zinc-900/5 transition-all"
                      placeholder="••••••••"
                    />
                  </div>
                  <button 
                    type="submit"
                    disabled={authLoading}
                    className="w-full bg-zinc-900 text-white py-3 rounded-2xl font-semibold hover:bg-zinc-800 transition-all active:scale-[0.98] disabled:opacity-50"
                  >
                    {authLoading ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : (authMode === 'login' ? 'Log In' : 'Sign Up')}
                  </button>
                </form>

                <div className="mt-6">
                  <div className="relative mb-6">
                    <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-zinc-100"></div></div>
                    <div className="relative flex justify-center text-xs uppercase tracking-widest font-bold text-zinc-400"><span className="bg-white px-2">Or continue with</span></div>
                  </div>
                  <button 
                    onClick={handleGoogleLogin}
                    className="w-full border border-zinc-200 py-3 rounded-2xl font-medium hover:bg-zinc-50 transition-all flex items-center justify-center gap-2"
                  >
                    <img src="https://www.google.com/favicon.ico" className="w-4 h-4" alt="Google" />
                    Google Account
                  </button>
                </div>

                <p className="mt-8 text-center text-sm text-zinc-500">
                  {authMode === 'login' ? "Don't have an account?" : "Already have an account?"}{' '}
                  <button 
                    onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}
                    className="text-zinc-900 font-bold hover:underline"
                  >
                    {authMode === 'login' ? 'Sign up' : 'Log in'}
                  </button>
                </p>
              </motion.div>
            </div>
          )}
        </AnimatePresence>

        {/* Header Section */}
        <div className="mb-12">
          <h1 className="text-4xl font-bold tracking-tight mb-2">File Repository</h1>
          <p className="text-zinc-500 max-w-2xl">
            Securely access, categorize, and manage shared documents. 
            {user ? ` Welcome, ${user.email}.` : ' Please log in to download files.'}
          </p>
        </div>

        {/* Notifications */}
        <AnimatePresence>
          {error && (
            <motion.div 
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="mb-6 p-4 bg-red-50 border border-red-100 rounded-xl flex items-center gap-3 text-red-700 text-sm"
            >
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <div className="flex-1">{error}</div>
              <button 
                onClick={() => {
                  setError(null);
                  fetchFiles();
                  if (sessionId) fetchUser();
                }}
                className="px-3 py-1 bg-red-100 hover:bg-red-200 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors"
              >
                Retry
              </button>
            </motion.div>
          )}
          {success && (
            <motion.div 
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="mb-6 p-4 bg-emerald-50 border border-emerald-100 rounded-xl flex items-center gap-3 text-emerald-700 text-sm"
            >
              <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
              {success}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Admin Dashboard */}
        {user?.isAdmin && (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-12 p-8 bg-white border border-zinc-200 rounded-3xl shadow-sm"
          >
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-5 h-5 text-zinc-900" />
                  <h2 className="text-xl font-bold">Admin Dashboard</h2>
                </div>
                <p className="text-sm text-zinc-500">Upload and categorize files for the repository.</p>
              </div>
              
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4">
                <div className="relative">
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-zinc-400 mb-1 ml-1">Category</label>
                  <div className="relative">
                    <select 
                      value={uploadCategory}
                      onChange={(e) => setUploadCategory(e.target.value)}
                      className="appearance-none w-full sm:w-48 pl-4 pr-10 py-2.5 bg-zinc-50 border border-zinc-200 rounded-xl text-sm font-medium focus:outline-none focus:ring-2 focus:ring-zinc-900/5 transition-all"
                    >
                      {CATEGORIES.map(cat => <option key={cat} value={cat}>{cat}</option>)}
                    </select>
                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400 pointer-events-none" />
                  </div>
                </div>

                <div className="relative">
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-zinc-400 mb-1 ml-1">Expiry Date (Optional)</label>
                  <input 
                    type="datetime-local"
                    value={uploadExpiry}
                    onChange={(e) => setUploadExpiry(e.target.value)}
                    className="w-full sm:w-48 px-4 py-2 bg-zinc-50 border border-zinc-200 rounded-xl text-sm font-medium focus:outline-none focus:ring-2 focus:ring-zinc-900/5 transition-all"
                  />
                </div>

                <div className="flex items-end">
                  <input 
                    type="file" 
                    ref={fileInputRef}
                    onChange={handleUpload}
                    className="hidden"
                  />
                  <button 
                    onClick={() => fileInputRef.current?.click()}
                    disabled={uploading}
                    className="flex items-center justify-center gap-2 bg-zinc-900 text-white px-6 py-2.5 rounded-xl font-medium hover:bg-zinc-800 transition-all disabled:opacity-50 shadow-lg shadow-zinc-200 h-[42px]"
                  >
                    {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                    {uploading ? 'Uploading...' : 'Upload File'}
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Search & Filter Bar */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-6 mb-10">
          <div className="flex-1 flex flex-col sm:flex-row items-stretch sm:items-center gap-4">
            <div className="relative flex-1 max-w-md flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
                <input 
                  type="text"
                  placeholder="Search by name or category..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-11 pr-4 py-3 bg-white border border-zinc-200 rounded-2xl focus:outline-none focus:ring-2 focus:ring-zinc-900/5 transition-all"
                />
              </div>
              <button 
                onClick={() => fetchFiles()}
                className="p-3 bg-white border border-zinc-200 rounded-2xl hover:bg-zinc-50 transition-all flex items-center justify-center text-zinc-600"
                title="Refresh file list"
              >
                <Loader2 className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
              </button>
              {user?.isAdmin && filteredFiles.length > 0 && (
                <button 
                  onClick={selectAll}
                  className={`p-3 border rounded-2xl transition-all flex items-center justify-center ${
                    selectedIds.length === filteredFiles.length 
                      ? 'bg-zinc-900 border-zinc-900 text-white' 
                      : 'bg-white border-zinc-200 text-zinc-600 hover:bg-zinc-50'
                  }`}
                  title={selectedIds.length === filteredFiles.length ? 'Deselect All' : 'Select All'}
                >
                  <CheckCircle2 className="w-5 h-5" />
                </button>
              )}
            </div>
            
            <div className="flex items-center gap-2 overflow-x-auto pb-2 sm:pb-0 scrollbar-hide">
              <button 
                onClick={() => setSelectedCategory('All')}
                className={`flex-shrink-0 px-4 py-2 rounded-xl text-sm font-medium transition-all ${selectedCategory === 'All' ? 'bg-zinc-900 text-white' : 'bg-white border border-zinc-200 text-zinc-600 hover:border-zinc-300'}`}
              >
                All
              </button>
              {CATEGORIES.map(cat => (
                <button 
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`flex-shrink-0 px-4 py-2 rounded-xl text-sm font-medium transition-all ${selectedCategory === cat ? 'bg-zinc-900 text-white' : 'bg-white border border-zinc-200 text-zinc-600 hover:border-zinc-300'}`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Bulk Actions Bar */}
        <AnimatePresence>
          {user?.isAdmin && selectedIds.length > 0 && (
            <motion.div 
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="mb-6 p-4 bg-zinc-900 text-white rounded-2xl flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xl"
            >
              <div className="flex items-center gap-4">
                <span className="text-sm font-bold bg-zinc-800 px-3 py-1 rounded-lg">
                  {selectedIds.length} Selected
                </span>
                <button 
                  onClick={selectAll}
                  className="text-sm font-medium hover:text-zinc-300 transition-colors"
                >
                  {selectedIds.length === filteredFiles.length ? 'Deselect All' : 'Select All'}
                </button>
              </div>
              <div className="flex items-center gap-3">
                {showBulkConfirm ? (
                  <div className="flex items-center gap-2 bg-zinc-800 p-1 rounded-xl">
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2">Confirm?</span>
                    <button 
                      onClick={() => setShowBulkConfirm(false)}
                      className="px-3 py-1.5 text-xs font-bold hover:bg-zinc-700 rounded-lg transition-colors"
                    >
                      No
                    </button>
                    <button 
                      onClick={() => {
                        handleBulkDelete();
                        setShowBulkConfirm(false);
                      }}
                      className="px-3 py-1.5 text-xs font-bold bg-red-500 hover:bg-red-600 rounded-lg transition-colors"
                    >
                      Yes, Delete
                    </button>
                  </div>
                ) : (
                  <>
                    <button 
                      onClick={() => setSelectedIds([])}
                      className="px-4 py-2 text-sm font-medium hover:bg-zinc-800 rounded-xl transition-colors"
                    >
                      Cancel
                    </button>
                    <button 
                      onClick={() => setShowBulkConfirm(true)}
                      disabled={isBulkDeleting}
                      className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white text-sm font-bold rounded-xl transition-colors flex items-center gap-2 disabled:opacity-50"
                    >
                      {isBulkDeleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                      {isBulkDeleting ? 'Deleting...' : 'Delete Selected'}
                    </button>
                  </>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* File Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <AnimatePresence mode="popLayout">
            {filteredFiles.map((file) => (
              <motion.div
                key={file.id}
                layout
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="group bg-white p-6 rounded-[2rem] border border-zinc-200 hover:border-zinc-300 hover:shadow-2xl hover:shadow-zinc-200/40 transition-all duration-500"
              >
                <div className="flex items-start justify-between mb-6">
                  <div className="flex items-center gap-4">
                    {user?.isAdmin && (
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleSelect(file.id);
                        }}
                        className={`w-6 h-6 rounded-lg border-2 flex items-center justify-center transition-all shadow-sm ${
                          selectedIds.includes(file.id) 
                            ? 'bg-zinc-900 border-zinc-900 text-white' 
                            : 'bg-white border-zinc-300 text-transparent hover:border-zinc-400'
                        }`}
                        title={selectedIds.includes(file.id) ? 'Deselect' : 'Select'}
                      >
                        <CheckCircle2 className="w-4 h-4" />
                      </button>
                    )}
                    <div className="w-14 h-14 bg-zinc-50 rounded-2xl flex items-center justify-center group-hover:bg-zinc-100 transition-colors duration-500">
                      {getFileIcon(file.mime_type, file.original_name)}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <button 
                      onClick={(e) => {
                        e.stopPropagation();
                        setPreviewFile(file);
                      }}
                      className="p-2.5 hover:bg-zinc-100 rounded-xl text-zinc-600 transition-colors"
                      title="Preview"
                    >
                      <Eye className="w-5 h-5" />
                    </button>
                    <button 
                      onClick={(e) => {
                        e.stopPropagation();
                        console.log(`Download icon clicked for file ${file.id}`);
                        handleDownload(file.id, file.original_name);
                      }}
                      className="p-2.5 hover:bg-zinc-100 rounded-xl text-zinc-600 transition-colors"
                      title="Download"
                    >
                      <Download className="w-5 h-5" />
                    </button>
                    {user?.isAdmin && (
                      <div className="relative">
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            setConfirmDeleteId(confirmDeleteId === file.id ? null : file.id);
                          }}
                          className={`p-2.5 rounded-xl transition-all ${
                            confirmDeleteId === file.id 
                              ? 'bg-red-500 text-white shadow-lg' 
                              : 'hover:bg-red-50 text-red-500'
                          }`}
                          title="Delete"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                        
                        <AnimatePresence>
                          {confirmDeleteId === file.id && (
                            <motion.div 
                              initial={{ opacity: 0, scale: 0.8, y: 10 }}
                              animate={{ opacity: 1, scale: 1, y: 0 }}
                              exit={{ opacity: 0, scale: 0.8, y: 10 }}
                              className="absolute right-0 top-full mt-2 z-50 bg-white border border-zinc-200 shadow-2xl rounded-2xl p-4 w-48"
                            >
                              <p className="text-xs font-bold text-zinc-900 mb-3">Delete this file?</p>
                              <div className="flex gap-2">
                                <button 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setConfirmDeleteId(null);
                                  }}
                                  className="flex-1 py-1.5 text-[10px] font-bold uppercase tracking-wider text-zinc-500 hover:bg-zinc-50 rounded-lg transition-colors"
                                >
                                  No
                                </button>
                                <button 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleDelete(file.id);
                                  }}
                                  className="flex-1 py-1.5 text-[10px] font-bold uppercase tracking-wider bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors"
                                >
                                  Yes
                                </button>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    )}
                  </div>
                </div>
                
                <div className="mb-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="inline-block px-2.5 py-1 bg-zinc-100 text-zinc-500 text-[10px] font-bold uppercase tracking-wider rounded-lg">
                      {file.category}
                    </span>
                    {user?.isAdmin && file.expiry_date && (
                      <span className="inline-block px-2.5 py-1 bg-red-50 text-red-500 text-[10px] font-bold uppercase tracking-wider rounded-lg flex items-center gap-1">
                        <AlertCircle className="w-3 h-3" />
                        Expires: {new Date(file.expiry_date).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                  <h3 className="font-bold text-zinc-900 text-lg leading-tight truncate" title={file.original_name}>
                    {file.original_name}
                  </h3>
                </div>
                
                <div className="flex items-center justify-between mt-auto pt-4 border-t border-zinc-50">
                  <div className="flex flex-col">
                    <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Size</span>
                    <span className="text-xs font-semibold text-zinc-600">{formatSize(file.size)}</span>
                  </div>
                  <div className="flex flex-col items-end">
                    <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Added</span>
                    <span className="text-xs font-semibold text-zinc-600">{new Date(file.upload_date).toLocaleDateString()}</span>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>

          {filteredFiles.length === 0 && (
            <div className="col-span-full py-32 flex flex-col items-center justify-center text-zinc-300">
              <div className="w-20 h-20 bg-zinc-100 rounded-full flex items-center justify-center mb-6">
                <FolderOpen className="w-10 h-10 opacity-20" />
              </div>
              <p className="text-lg font-semibold text-zinc-400">No files found in this category</p>
              <p className="text-sm text-zinc-400 mt-1">Try adjusting your search or filters</p>
            </div>
          )}
        </div>
      </main>

      <AnimatePresence>
        {previewFile && renderPreview()}
      </AnimatePresence>

      {/* Debug Info */}
      <div className="max-w-6xl mx-auto px-4 mb-8">
        <div className="p-4 bg-zinc-100 rounded-2xl border border-zinc-200">
          <p className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-2">Debug Information</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-[10px] font-mono text-zinc-500">
            <div>User: {user ? user.email : 'Not logged in'}</div>
            <div>Role: {user ? user.role : 'Guest'}</div>
            <div>IsAdmin: {user?.isAdmin ? 'Yes' : 'No'}</div>
            <div>Session: {sessionId ? `${sessionId.substring(0, 8)}...` : 'None'}</div>
            <div>Files: {files.length}</div>
            <div>Google Auth: {import.meta.env.VITE_GOOGLE_CLIENT_ID ? 'Configured' : 'Missing VITE_GOOGLE_CLIENT_ID'}</div>
            <div>App URL: {import.meta.env.VITE_APP_URL || 'Not set (using window.origin)'}</div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="mt-20 border-t border-zinc-200 py-16 bg-white">
        <div className="max-w-6xl mx-auto px-4">
          <div className="flex flex-col md:flex-row items-center justify-between gap-8">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-zinc-400" />
              <span className="text-sm font-bold uppercase tracking-[0.2em] text-zinc-400">SecureShare Protocol</span>
            </div>
            <div className="flex items-center gap-8 text-sm font-medium text-zinc-400">
              <a href="#" className="hover:text-zinc-900 transition-colors">Privacy</a>
              <a href="#" className="hover:text-zinc-900 transition-colors">Terms</a>
              <a href="#" className="hover:text-zinc-900 transition-colors">Security</a>
            </div>
          </div>
          <div className="mt-12 pt-8 border-t border-zinc-50 text-center md:text-left">
            <p className="text-xs text-zinc-400 font-medium tracking-wide">
              &copy; {new Date().getFullYear()} SecureShare. Enterprise-grade file distribution system.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}


