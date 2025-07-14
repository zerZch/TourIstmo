// ===============================
// SISTEMA DE LOGIN COMPLETO - PÁGINA STANDALONE
// Preparado para integración con JSP + MySQL
// ===============================

document.addEventListener('DOMContentLoaded', function () {
    
    // ===============================
    // CONFIGURACIÓN Y VARIABLES
    // ===============================
    
    const CONFIG = {
        // URLs del backend (ajustar según tu estructura de proyecto)
        API_BASE_URL: '/touristmo/api',
        LOGIN_ENDPOINT: '/auth/login',
        REGISTER_ENDPOINT: '/auth/register',
        FORGOT_PASSWORD_ENDPOINT: '/auth/forgot-password',
        VERIFY_EMAIL_ENDPOINT: '/auth/verify-email',
        SOCIAL_LOGIN_ENDPOINT: '/auth/social',
        
        // Configuración de validación
        PASSWORD_MIN_LENGTH: 8,
        MAX_LOGIN_ATTEMPTS: 3,
        LOCKOUT_DURATION: 300000, // 5 minutos en ms
        
        // Configuración de seguridad
        SESSION_TIMEOUT: 1800000, // 30 minutos
        REMEMBER_ME_DURATION: 604800000, // 7 días
        
        // Mensajes
        MESSAGES: {
            REQUIRED_EMAIL: 'El email es obligatorio',
            INVALID_EMAIL: 'Formato de email inválido',
            REQUIRED_PASSWORD: 'La contraseña es obligatoria',
            INVALID_PASSWORD: 'La contraseña debe tener al menos 8 caracteres',
            LOGIN_SUCCESS: 'Inicio de sesión exitoso',
            LOGIN_ERROR: 'Credenciales incorrectas',
            NETWORK_ERROR: 'Error de conexión. Intente nuevamente',
            ACCOUNT_LOCKED: 'Cuenta bloqueada. Intente en 5 minutos',
            SESSION_EXPIRED: 'Sesión expirada. Inicie sesión nuevamente'
        }
    };

    // Variables globales
    let isSubmitting = false;
    let loginAttempts = parseInt(localStorage.getItem('loginAttempts') || '0');
    let lockoutEndTime = parseInt(localStorage.getItem('lockoutEndTime') || '0');
    let sessionTimeout = null;
    let rememberMeToken = localStorage.getItem('rememberMeToken');

    // Elementos DOM
    const elements = {
        loginForm: document.getElementById('loginForm'),
        emailInput: document.getElementById('email'),
        passwordInput: document.getElementById('password'),
        rememberCheckbox: document.getElementById('remember'),
        submitButton: document.getElementById('submitButton'),
        loadingSpinner: document.getElementById('loadingSpinner'),
        
        // Mensajes de error
        emailError: document.getElementById('emailError'),
        passwordError: document.getElementById('passwordError'),
        generalError: document.getElementById('generalError'),
        
        // Enlaces y botones adicionales
        forgotPasswordLink: document.getElementById('forgotPasswordLink'),
        registerLink: document.getElementById('registerLink'),
        googleLoginBtn: document.getElementById('googleLoginBtn'),
        facebookLoginBtn: document.getElementById('facebookLoginBtn'),
        
        // Elementos de UI
        passwordToggle: document.getElementById('passwordToggle'),
        demoCredentialsBtn: document.getElementById('demoCredentialsBtn'),
        
        // Elementos de notificación
        notificationContainer: document.getElementById('notificationContainer')
    };

    // ===============================
    // UTILIDADES Y HELPERS
    // ===============================
    
    const Utils = {
        // Validación de email
        isValidEmail: (email) => {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        },
        
        // Validación de contraseña
        isValidPassword: (password) => {
            return password.length >= CONFIG.PASSWORD_MIN_LENGTH;
        },
        
        // Sanitización de inputs
        sanitizeInput: (input) => {
            return input.trim().replace(/[<>]/g, '');
        },
        
        // Generación de token CSRF (simulado)
        generateCSRFToken: () => {
            return Math.random().toString(36).substr(2, 9);
        },
        
        // Formateo de fechas
        formatDate: (date) => {
            return new Intl.DateTimeFormat('es-ES', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            }).format(date);
        },
        
        // Logging para debugging
        log: (message, level = 'info') => {
            const timestamp = new Date().toISOString();
            console[level](`[${timestamp}] LOGIN: ${message}`);
        },
        
        // Debounce para validación en tiempo real
        debounce: (func, wait) => {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
    };

    // ===============================
    // GESTIÓN DE SESIÓN
    // ===============================
    
    const SessionManager = {
        // Iniciar sesión
        startSession: (userData, rememberMe = false) => {
            const sessionData = {
                user: userData,
                loginTime: Date.now(),
                expiresAt: Date.now() + CONFIG.SESSION_TIMEOUT,
                csrfToken: Utils.generateCSRFToken()
            };
            
            sessionStorage.setItem('userSession', JSON.stringify(sessionData));
            
            if (rememberMe) {
                const rememberToken = Utils.generateCSRFToken();
                localStorage.setItem('rememberMeToken', rememberToken);
                localStorage.setItem('rememberMeExpiry', Date.now() + CONFIG.REMEMBER_ME_DURATION);
            }
            
            SessionManager.startSessionTimer();
            Utils.log(`Sesión iniciada para usuario: ${userData.email}`);
        },
        
        // Verificar sesión activa
        isSessionActive: () => {
            const sessionData = sessionStorage.getItem('userSession');
            if (!sessionData) return false;
            
            const session = JSON.parse(sessionData);
            return Date.now() < session.expiresAt;
        },
        
        // Renovar sesión
        renewSession: () => {
            const sessionData = sessionStorage.getItem('userSession');
            if (sessionData) {
                const session = JSON.parse(sessionData);
                session.expiresAt = Date.now() + CONFIG.SESSION_TIMEOUT;
                sessionStorage.setItem('userSession', JSON.stringify(session));
                SessionManager.startSessionTimer();
            }
        },
        
        // Terminar sesión
        endSession: () => {
            sessionStorage.removeItem('userSession');
            if (!elements.rememberCheckbox?.checked) {
                localStorage.removeItem('rememberMeToken');
                localStorage.removeItem('rememberMeExpiry');
            }
            clearTimeout(sessionTimeout);
            Utils.log('Sesión terminada');
        },
        
        // Timer de sesión
        startSessionTimer: () => {
            clearTimeout(sessionTimeout);
            sessionTimeout = setTimeout(() => {
                NotificationManager.show(CONFIG.MESSAGES.SESSION_EXPIRED, 'warning');
                SessionManager.endSession();
                // Redirigir al login si es necesario
                window.location.reload();
            }, CONFIG.SESSION_TIMEOUT);
        },
        
        // Verificar remember me
        checkRememberMe: () => {
            const token = localStorage.getItem('rememberMeToken');
            const expiry = localStorage.getItem('rememberMeExpiry');
            
            if (token && expiry && Date.now() < parseInt(expiry)) {
                // Intentar login automático
                AuthManager.autoLogin(token);
                return true;
            }
            
            return false;
        }
    };

    // ===============================
    // GESTIÓN DE AUTENTICACIÓN
    // ===============================
    
    const AuthManager = {
        // Login principal
        login: async (credentials) => {
            try {
                const response = await fetch(CONFIG.API_BASE_URL + CONFIG.LOGIN_ENDPOINT, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        email: credentials.email,
                        password: credentials.password,
                        rememberMe: credentials.rememberMe,
                        csrfToken: Utils.generateCSRFToken(),
                        browserInfo: {
                            userAgent: navigator.userAgent,
                            language: navigator.language,
                            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                        }
                    })
                });

                const data = await response.json();
                
                if (response.ok && data.success) {
                    // Reset intentos de login
                    AuthManager.resetLoginAttempts();
                    
                    // Iniciar sesión
                    SessionManager.startSession(data.user, credentials.rememberMe);
                    
                    // Redireccionar
                    AuthManager.redirectAfterLogin(data.redirectUrl);
                    
                    return { success: true, data };
                } else {
                    // Incrementar intentos fallidos
                    AuthManager.incrementLoginAttempts();
                    
                    return { 
                        success: false, 
                        error: data.message || CONFIG.MESSAGES.LOGIN_ERROR 
                    };
                }
                
            } catch (error) {
                Utils.log(`Error en login: ${error.message}`, 'error');
                return { 
                    success: false, 
                    error: CONFIG.MESSAGES.NETWORK_ERROR 
                };
            }
        },
        
        // Auto login con remember me
        autoLogin: async (token) => {
            try {
                const response = await fetch(CONFIG.API_BASE_URL + '/auth/auto-login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });

                const data = await response.json();
                
                if (response.ok && data.success) {
                    SessionManager.startSession(data.user, true);
                    AuthManager.redirectAfterLogin(data.redirectUrl);
                }
                
            } catch (error) {
                Utils.log(`Error en auto login: ${error.message}`, 'error');
                localStorage.removeItem('rememberMeToken');
                localStorage.removeItem('rememberMeExpiry');
            }
        },
        
        // Social login
        socialLogin: async (provider) => {
            try {
                // Redirigir a la URL de OAuth del proveedor
                const socialUrl = `${CONFIG.API_BASE_URL}${CONFIG.SOCIAL_LOGIN_ENDPOINT}/${provider}`;
                window.location.href = socialUrl;
                
            } catch (error) {
                Utils.log(`Error en social login: ${error.message}`, 'error');
                NotificationManager.show('Error al conectar con ' + provider, 'error');
            }
        },
        
        // Forgot password
        forgotPassword: async (email) => {
            try {
                const response = await fetch(CONFIG.API_BASE_URL + CONFIG.FORGOT_PASSWORD_ENDPOINT, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email })
                });

                const data = await response.json();
                return data;
                
            } catch (error) {
                Utils.log(`Error en forgot password: ${error.message}`, 'error');
                return { 
                    success: false, 
                    error: CONFIG.MESSAGES.NETWORK_ERROR 
                };
            }
        },
        
        // Gestión de intentos de login
        incrementLoginAttempts: () => {
            loginAttempts++;
            localStorage.setItem('loginAttempts', loginAttempts.toString());
            
            if (loginAttempts >= CONFIG.MAX_LOGIN_ATTEMPTS) {
                lockoutEndTime = Date.now() + CONFIG.LOCKOUT_DURATION;
                localStorage.setItem('lockoutEndTime', lockoutEndTime.toString());
                UIManager.showLockout();
            }
        },
        
        resetLoginAttempts: () => {
            loginAttempts = 0;
            lockoutEndTime = 0;
            localStorage.removeItem('loginAttempts');
            localStorage.removeItem('lockoutEndTime');
        },
        
        // Verificar bloqueo
        isAccountLocked: () => {
            return Date.now() < lockoutEndTime;
        },
        
        // Redirección después del login
        redirectAfterLogin: (redirectUrl) => {
            setTimeout(() => {
                window.location.href = redirectUrl || '/touristmo/dashboard';
            }, 1500);
        }
    };

    // ===============================
    // GESTIÓN DE INTERFAZ
    // ===============================
    
    const UIManager = {
        // Mostrar/ocultar loading
        showLoading: (show = true) => {
            if (elements.loadingSpinner) {
                elements.loadingSpinner.style.display = show ? 'inline-block' : 'none';
            }
            
            if (elements.submitButton) {
                elements.submitButton.disabled = show;
                elements.submitButton.textContent = show ? 'Iniciando sesión...' : 'Iniciar Sesión';
            }
            
            isSubmitting = show;
        },
        
        // Mostrar errores
        showError: (field, message) => {
            const errorElement = elements[field + 'Error'];
            const inputElement = elements[field + 'Input'];
            
            if (errorElement && inputElement) {
                errorElement.textContent = message;
                errorElement.classList.add('show');
                inputElement.classList.add('error');
                
                // Animación de shake
                inputElement.style.animation = 'shake 0.5s ease-in-out';
                setTimeout(() => {
                    inputElement.style.animation = '';
                }, 500);
            }
        },
        
        // Limpiar errores
        clearError: (field) => {
            const errorElement = elements[field + 'Error'];
            const inputElement = elements[field + 'Input'];
            
            if (errorElement && inputElement) {
                errorElement.textContent = '';
                errorElement.classList.remove('show');
                inputElement.classList.remove('error');
            }
        },
        
        // Limpiar todos los errores
        clearAllErrors: () => {
            ['email', 'password', 'general'].forEach(field => {
                UIManager.clearError(field);
            });
        },
        
        // Mostrar bloqueo de cuenta
        showLockout: () => {
            const timeLeft = Math.ceil((lockoutEndTime - Date.now()) / 1000 / 60);
            const message = `${CONFIG.MESSAGES.ACCOUNT_LOCKED} (${timeLeft} minutos restantes)`;
            
            if (elements.generalError) {
                elements.generalError.textContent = message;
                elements.generalError.classList.add('show');
            }
            
            if (elements.submitButton) {
                elements.submitButton.disabled = true;
            }
            
            // Timer para habilitar el formulario
            setTimeout(() => {
                AuthManager.resetLoginAttempts();
                UIManager.clearAllErrors();
                if (elements.submitButton) {
                    elements.submitButton.disabled = false;
                }
            }, CONFIG.LOCKOUT_DURATION);
        },
        
        // Toggle password visibility
        togglePasswordVisibility: () => {
            if (elements.passwordInput && elements.passwordToggle) {
                const isPassword = elements.passwordInput.type === 'password';
                elements.passwordInput.type = isPassword ? 'text' : 'password';
                elements.passwordToggle.textContent = isPassword ? '👁️' : '🔒';
            }
        },
        
        // Mostrar credenciales demo
        showDemoCredentials: () => {
            const credentials = [
                { email: 'demo@touristmo.com', password: 'demo123', role: 'Usuario Demo' },
                { email: 'admin@touristmo.com', password: 'admin123', role: 'Administrador' },
                { email: 'guide@touristmo.com', password: 'guide123', role: 'Guía Turístico' }
            ];
            
            let message = 'Credenciales de prueba:\\n\\n';
            credentials.forEach(cred => {
                message += `${cred.role}:\\n📧 ${cred.email}\\n🔒 ${cred.password}\\n\\n`;
            });
            
            alert(message);
        }
    };

    // ===============================
    // GESTIÓN DE NOTIFICACIONES
    // ===============================
    
    const NotificationManager = {
        show: (message, type = 'info', duration = 5000) => {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <span class="notification-icon">${NotificationManager.getIcon(type)}</span>
                    <span class="notification-message">${message}</span>
                    <button class="notification-close">×</button>
                </div>
            `;
            
            // Agregar al contenedor
            if (elements.notificationContainer) {
                elements.notificationContainer.appendChild(notification);
            } else {
                document.body.appendChild(notification);
            }
            
            // Evento de cierre
            notification.querySelector('.notification-close').addEventListener('click', () => {
                NotificationManager.hide(notification);
            });
            
            // Auto-hide
            setTimeout(() => {
                NotificationManager.hide(notification);
            }, duration);
        },
        
        hide: (notification) => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => {
                notification.remove();
            }, 300);
        },
        
        getIcon: (type) => {
            const icons = {
                success: '✅',
                error: '❌',
                warning: '⚠️',
                info: 'ℹ️'
            };
            return icons[type] || icons.info;
        }
    };

    // ===============================
    // VALIDACIÓN DE FORMULARIO
    // ===============================
    
    const FormValidator = {
        // Validar email
        validateEmail: (email) => {
            if (!email) {
                return CONFIG.MESSAGES.REQUIRED_EMAIL;
            }
            if (!Utils.isValidEmail(email)) {
                return CONFIG.MESSAGES.INVALID_EMAIL;
            }
            return null;
        },
        
        // Validar contraseña
        validatePassword: (password) => {
            if (!password) {
                return CONFIG.MESSAGES.REQUIRED_PASSWORD;
            }
            if (!Utils.isValidPassword(password)) {
                return CONFIG.MESSAGES.INVALID_PASSWORD;
            }
            return null;
        },
        
        // Validar formulario completo
        validateForm: () => {
            let isValid = true;
            UIManager.clearAllErrors();
            
            // Validar email
            const email = elements.emailInput?.value?.trim() || '';
            const emailError = FormValidator.validateEmail(email);
            if (emailError) {
                UIManager.showError('email', emailError);
                isValid = false;
            }
            
            // Validar contraseña
            const password = elements.passwordInput?.value || '';
            const passwordError = FormValidator.validatePassword(password);
            if (passwordError) {
                UIManager.showError('password', passwordError);
                isValid = false;
            }
            
            return isValid;
        }
    };

    // ===============================
    // MANEJO DE EVENTOS
    // ===============================
    
    const EventHandlers = {
        // Submit del formulario
        handleFormSubmit: async (event) => {
            event.preventDefault();
            
            if (isSubmitting || AuthManager.isAccountLocked()) {
                return;
            }
            
            if (!FormValidator.validateForm()) {
                return;
            }
            
            const credentials = {
                email: Utils.sanitizeInput(elements.emailInput.value),
                password: elements.passwordInput.value,
                rememberMe: elements.rememberCheckbox?.checked || false
            };
            
            UIManager.showLoading(true);
            
            try {
                const result = await AuthManager.login(credentials);
                
                if (result.success) {
                    NotificationManager.show(CONFIG.MESSAGES.LOGIN_SUCCESS, 'success');
                } else {
                    UIManager.showError('general', result.error);
                }
                
            } catch (error) {
                UIManager.showError('general', CONFIG.MESSAGES.NETWORK_ERROR);
                Utils.log(`Error en submit: ${error.message}`, 'error');
            } finally {
                UIManager.showLoading(false);
            }
        },
        
        // Validación en tiempo real
        handleRealTimeValidation: Utils.debounce((field, value) => {
            if (value.trim()) {
                let error = null;
                
                if (field === 'email') {
                    error = FormValidator.validateEmail(value);
                } else if (field === 'password') {
                    error = FormValidator.validatePassword(value);
                }
                
                if (error) {
                    UIManager.showError(field, error);
                } else {
                    UIManager.clearError(field);
                }
            } else {
                UIManager.clearError(field);
            }
        }, 300),
        
        // Forgot password
        handleForgotPassword: async (event) => {
            event.preventDefault();
            
            const email = elements.emailInput?.value?.trim();
            if (!email) {
                UIManager.showError('email', CONFIG.MESSAGES.REQUIRED_EMAIL);
                return;
            }
            
            if (!Utils.isValidEmail(email)) {
                UIManager.showError('email', CONFIG.MESSAGES.INVALID_EMAIL);
                return;
            }
            
            try {
                const result = await AuthManager.forgotPassword(email);
                
                if (result.success) {
                    NotificationManager.show(
                        'Se ha enviado un enlace de recuperación a tu email', 
                        'success'
                    );
                } else {
                    NotificationManager.show(result.error, 'error');
                }
                
            } catch (error) {
                NotificationManager.show(CONFIG.MESSAGES.NETWORK_ERROR, 'error');
            }
        },
        
        // Social login
        handleSocialLogin: (provider) => {
            AuthManager.socialLogin(provider);
        }
    };

    // ===============================
    // INICIALIZACIÓN
    // ===============================
    
    const init = () => {
        Utils.log('Inicializando sistema de login');
        
        // Verificar bloqueo de cuenta
        if (AuthManager.isAccountLocked()) {
            UIManager.showLockout();
        }
        
        // Verificar remember me
        if (SessionManager.checkRememberMe()) {
            return; // Auto login en progreso
        }
        
        // Configurar event listeners
        setupEventListeners();
        
        // Configurar validación en tiempo real
        setupRealTimeValidation();
        
        // Configurar UI inicial
        setupInitialUI();
        
        Utils.log('Sistema de login inicializado correctamente');
    };

    const setupEventListeners = () => {
        // Formulario principal
        if (elements.loginForm) {
            elements.loginForm.addEventListener('submit', EventHandlers.handleFormSubmit);
        }
        
        // Toggle password
        if (elements.passwordToggle) {
            elements.passwordToggle.addEventListener('click', UIManager.togglePasswordVisibility);
        }
        
        // Forgot password
        if (elements.forgotPasswordLink) {
            elements.forgotPasswordLink.addEventListener('click', EventHandlers.handleForgotPassword);
        }
        
        // Social login
        if (elements.googleLoginBtn) {
            elements.googleLoginBtn.addEventListener('click', () => {
                EventHandlers.handleSocialLogin('google');
            });
        }
        
        if (elements.facebookLoginBtn) {
            elements.facebookLoginBtn.addEventListener('click', () => {
                EventHandlers.handleSocialLogin('facebook');
            });
        }
        
        // Demo credentials
        if (elements.demoCredentialsBtn) {
            elements.demoCredentialsBtn.addEventListener('click', UIManager.showDemoCredentials);
        }
    };

    const setupRealTimeValidation = () => {
        // Email validation
        if (elements.emailInput) {
            elements.emailInput.addEventListener('input', (e) => {
                EventHandlers.handleRealTimeValidation('email', e.target.value);
            });
        }
        
        // Password validation
        if (elements.passwordInput) {
            elements.passwordInput.addEventListener('input', (e) => {
                EventHandlers.handleRealTimeValidation('password', e.target.value);
            });
        }
    };

    const setupInitialUI = () => {
        // Focus en email input
        if (elements.emailInput) {
            elements.emailInput.focus();
        }
        
        // Cargar email recordado
        const rememberedEmail = localStorage.getItem('rememberedEmail');
        if (rememberedEmail && elements.emailInput) {
            elements.emailInput.value = rememberedEmail;
            if (elements.rememberCheckbox) {
                elements.rememberCheckbox.checked = true;
            }
        }
    };

    // ===============================
    // INICIALIZAR APLICACIÓN
    // ===============================
    
    init();
    
    // Exponer funciones globales si es necesario
    window.LoginSystem = {
        login: AuthManager.login,
        logout: SessionManager.endSession,
        isAuthenticated: SessionManager.isSessionActive,
        showNotification: NotificationManager.show
    };
});

// ===============================
// ESTILOS CSS ADICIONALES PARA NOTIFICACIONES
// ===============================

const additionalStyles = `
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        min-width: 300px;
        max-width: 500px;
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    }
    
    .notification-content {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        background: white;
        border-left: 4px solid;
    }
    
    .notification-success .notification-content {
        border-left-color: #4CAF50;
        background: #E8F5E8;
    }
    
    .notification-error .notification-content {
        border-left-color: #E74C3C;
        background: #FDEAEA;
    }
    
    .notification-warning .notification-content {
        border-left-color: #FFA726;
        background: #FFF3E0;
    }
    
    .notification-info .notification-content {
        border-left-color: #2196F3;
        background: #E3F2FD;
    }
    
    .notification-close {
        background: none;
        border: none;
        font-size: 18px;
        cursor: pointer;
        opacity: 0.7;
        margin-left: auto;
    }
    
    .notification-close:hover {
        opacity: 1;
    }
    
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;

// Agregar estilos al documento
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalStyles;
document.head.appendChild(styleSheet);