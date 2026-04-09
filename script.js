document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const passwordStrength = document.getElementById('passwordStrength');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const generatedPasswordInput = document.getElementById('generatedPassword');
    const generatePasswordBtn = document.getElementById('generatePasswordBtn');
    const useGeneratedPasswordBtn = document.getElementById('useGeneratedPasswordBtn');
    const registrationForm = document.getElementById('registrationForm');
    const loginForm = document.getElementById('loginForm');
    const resetPasswordForm = document.getElementById('resetPasswordForm');
    const countryCodeSelect = document.getElementById('countryCode');

    async function postFormWithCsrf(url, formData) {
        const execute = async function(forceRefresh) {
            let token = '';
            if (window.ensureCsrfToken) {
                token = await window.ensureCsrfToken(!!forceRefresh);
            }

            const headers = window.withCsrfHeaders ? window.withCsrfHeaders() : {};

            // Send token in form body too as a fallback for environments
            // where custom headers may be stripped.
            const requestFormData = new FormData();
            formData.forEach((value, key) => {
                requestFormData.append(key, value);
            });

            if (token) {
                requestFormData.set('_csrf', token);
            }

            const response = await fetch(url, {
                method: 'POST',
                headers: headers,
                body: requestFormData
            });

            const text = await response.text();
            let data;
            try {
                data = JSON.parse(text);
            } catch (e) {
                throw new Error(text || 'Server returned an invalid response.');
            }

            return data;
        };

        let data = await execute(false);
        const invalidCsrfMessage = 'Invalid security token. Please refresh and try again.';

        if ((data.message === invalidCsrfMessage || data.status === 'error' && data.message === invalidCsrfMessage) && window.ensureCsrfToken) {
            data = await execute(true);
        }

        return data;
    }

    if (window.ensureCsrfToken) {
        window.ensureCsrfToken().catch(() => {
            // Continue gracefully; protected endpoints will still validate on server.
        });
    }

    function getRandomInt(max) {
        if (!max || max <= 0) {
            return 0;
        }

        if (window.crypto && window.crypto.getRandomValues) {
            const array = new Uint32Array(1);
            window.crypto.getRandomValues(array);
            return array[0] % max;
        }

        return Math.floor(Math.random() * max);
    }

    function shuffleCharacters(characters) {
        const array = characters.split('');
        for (let index = array.length - 1; index > 0; index--) {
            const swapIndex = getRandomInt(index + 1);
            [array[index], array[swapIndex]] = [array[swapIndex], array[index]];
        }
        return array.join('');
    }

    function createStrongPassword(length = 12) {
        const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const lower = 'abcdefghijklmnopqrstuvwxyz';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*()_+';
        const allChars = upper + lower + numbers + symbols;

        let password = '';
        password += upper[getRandomInt(upper.length)];
        password += lower[getRandomInt(lower.length)];
        password += numbers[getRandomInt(numbers.length)];
        password += symbols[getRandomInt(symbols.length)];

        for (let index = 4; index < length; index++) {
            password += allChars[getRandomInt(allChars.length)];
        }

        return shuffleCharacters(password);
    }

    window.generatePassword = function() {
        if (!generatedPasswordInput) {
            return;
        }

        generatedPasswordInput.value = createStrongPassword(12);
    };

    window.usePassword = function() {
        if (!generatedPasswordInput || !passwordInput) {
            return;
        }

        const generated = generatedPasswordInput.value;
        if (!generated) {
            window.generatePassword();
        }

        passwordInput.value = generatedPasswordInput.value;
        if (confirmPasswordInput) {
            confirmPasswordInput.value = generatedPasswordInput.value;
        }

        passwordInput.dispatchEvent(new Event('input'));
    };

    if (generatePasswordBtn) {
        generatePasswordBtn.addEventListener('click', function() {
            window.generatePassword();
        });
    }

    if (useGeneratedPasswordBtn) {
        useGeneratedPasswordBtn.addEventListener('click', function() {
            window.usePassword();
        });
    }

    // Populate country codes from REST Countries API
    if (countryCodeSelect) {
        // Show loading message
        const loadingOption = document.createElement('option');
        loadingOption.textContent = 'Loading countries...';
        loadingOption.disabled = true;
        countryCodeSelect.appendChild(loadingOption);

        fetch('https://restcountries.com/v3.1/all?fields=name,cca2,idd')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(countries => {
                // Clear loading option
                countryCodeSelect.innerHTML = '<option value="">Select Country</option>';

                // Process countries and extract unique country codes
                const countryMap = new Map();
                countries.forEach(country => {
                    if (country.idd && country.idd.root) {
                        let code = country.idd.root;
                        if (country.idd.suffixes && country.idd.suffixes.length > 0) {
                            // Use the first suffix for the main code
                            code += country.idd.suffixes[0];
                        }
                        // Avoid duplicates
                        if (!countryMap.has(code)) {
                            countryMap.set(code, country.name.common);
                        }
                    }
                });

                // Sort countries alphabetically and populate select
                const sortedCountries = Array.from(countryMap.entries()).sort((a, b) => a[1].localeCompare(b[1]));

                sortedCountries.forEach(([code, name]) => {
                    const option = document.createElement('option');
                    option.value = code;
                    option.textContent = `${name} (${code})`;
                    countryCodeSelect.appendChild(option);
                });

                console.log(`Loaded ${countryMap.size} countries with phone codes`);
            })
            .catch(error => {
                console.error('Error fetching countries:', error);
                // Fallback to hardcoded list
                countryCodeSelect.innerHTML = '<option value="">Select Country</option>';
                const fallbackCountries = [
                    { name: 'United States', code: '+1' },
                    { name: 'United Kingdom', code: '+44' },
                    { name: 'India', code: '+91' },
                    { name: 'Australia', code: '+61' },
                    { name: 'Japan', code: '+81' },
                    { name: 'Germany', code: '+49' },
                    { name: 'France', code: '+33' },
                    { name: 'Canada', code: '+1' },
                    { name: 'China', code: '+86' },
                    { name: 'Brazil', code: '+55' }
                ];

                fallbackCountries.forEach(country => {
                    const option = document.createElement('option');
                    option.value = country.code;
                    option.textContent = `${country.name} (${country.code})`;
                    countryCodeSelect.appendChild(option);
                });

                console.log('Using fallback country list due to API error');
            });
    }

    if (passwordInput) {
        // Password strength checker
        function checkPasswordStrength(password) {
            let strength = 0;
            let feedback = [];

            if (password.length >= 8) strength++;
            else feedback.push('At least 8 characters');

            if (/[a-z]/.test(password)) strength++;
            else feedback.push('Lowercase letter');

            if (/[A-Z]/.test(password)) strength++;
            else feedback.push('Uppercase letter');

            if (/\d/.test(password)) strength++;
            else feedback.push('Number');

            if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) strength++;
            else feedback.push('Special character');

            let className, text;
            if (strength < 3) {
                className = 'weak';
                text = 'Weak: ' + feedback.join(', ');
            } else if (strength < 5) {
                className = 'medium';
                text = 'Medium: ' + feedback.join(', ');
            } else {
                className = 'strong';
                text = 'Strong';
            }

            passwordStrength.className = className;
            passwordStrength.textContent = text;
        }

        passwordInput.addEventListener('input', function() {
            checkPasswordStrength(this.value);
        });
    }

    // For change password and reset password forms
    const newPasswordInput = document.getElementById('newPassword');
    if (newPasswordInput) {
        newPasswordInput.addEventListener('input', function() {
            checkPasswordStrength(this.value);
        });
    }

    if (registrationForm) {
        registrationForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const password = passwordInput.value;
            const confirmPassword = confirmPasswordInput.value;

            if (password !== confirmPassword) {
                showMessage('Passwords do not match', 'error');
                return;
            }

            // Turnstile will be validated server-side
            const formData = new FormData(this);
            if (!formData.get('cf-turnstile-response')) {
                showMessage('Please complete the CAPTCHA verification before submitting.', 'error');
                return;
            }

            postFormWithCsrf('register.php', formData)
            .then(data => {
                if (data.status === 'success') {
                    window.location.href = data.redirect;
                } else {
                    showMessage(data.message, 'error');
                }
            })
            .catch(error => {
                showMessage(error.message || 'An error occurred', 'error');
            });
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);

            if (!formData.get('cf-turnstile-response')) {
                showMessage('Please complete the CAPTCHA verification before submitting.', 'error');
                return;
            }

            postFormWithCsrf('login.php', formData)
            .then(data => {
                if (data.success) {
                    if (data.requires_2fa) {
                        showMessage(data.message, 'info');
                        // Redirect to 2FA page
                        setTimeout(() => {
                            window.location.href = 'login_verify_2fa.html';
                        }, 1000);
                    } else {
                        showMessage(data.message, 'success');
                        // Redirect to dashboard
                        setTimeout(() => {
                            window.location.href = 'dashboard.html';
                        }, 1000);
                    }
                } else {
                    if (data.requires_password_change) {
                        showMessage(data.message + ' Redirecting to change password...', 'warning');
                        setTimeout(() => {
                            window.location.href = 'change_password.html';
                        }, 2000);
                    } else {
                        showMessage(data.message, 'error');
                    }
                }
            })
            .catch(error => {
                showMessage('An error occurred', 'error');
            });
        });
    }

    if (resetPasswordForm) {
        resetPasswordForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);

            postFormWithCsrf('reset_password.php', formData)
            .then(data => {
                if (data.success) {
                    showMessage(data.message, 'success');
                    // Redirect to login after a delay
                    setTimeout(() => {
                        window.location.href = 'login.html';
                    }, 2000);
                } else {
                    showMessage(data.message, 'error');
                }
            })
            .catch(error => {
                showMessage('An error occurred', 'error');
            });
        });
    }

    function showMessage(text, type) {
        const messageDiv = document.getElementById('message');
        if (messageDiv) {
            messageDiv.textContent = text;
            messageDiv.className = type;
        }
    }

    // Password toggle function
    window.togglePassword = function(inputId, button) {
        const input = document.getElementById(inputId);
        if (input.type === 'password') {
            input.type = 'text';
            button.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            input.type = 'password';
            button.innerHTML = '<i class="fas fa-eye"></i>';
        }
    }
});