window.onload = () => {
    const passwordController = new PasswordController();
    passwordController.setupListeners();
};

class PasswordController {
    constructor() {
        this.passwordField = document.getElementById('password');
        this.passwordRepeatField = document.getElementById('password-repeat');
        this.form = document.forms[0];

        this.passwordTiers = [5, 10, 15];
        this.passwordMessages = ['Słabe', 'Średnie', 'Silne', 'Bardzo silne'];
        this.passwordClassNames = ['weak', 'average', 'strong', 'very-strong'];
    }

    setupListeners() {
        this.passwordField.addEventListener('keyup', this.controlPassword);
        this.passwordRepeatField.addEventListener('keyup', this.controlRepeatPassword);
        this.form.addEventListener('submit', this.controlForm);
    }

    controlPassword = () => {
        const val = this.passwordField.value;
        if (val.length < 8) {
            return this.addMessage(this.passwordField, 'Hasło musi zawierać co najmniej 8 znaków.', 'form-wrong', 'password-message');
        }
        const strength = calculatePasswordStrength(val);
        for (const idx in this.passwordTiers) {
            if (strength < this.passwordTiers[idx]) {
                return this.addPasswordMessage(this.passwordMessages[idx], this.passwordClassNames[idx]);
            }
        }
        this.addPasswordMessage(this.passwordMessages[this.passwordMessages.length - 1], this.passwordClassNames[this.passwordClassNames.length - 1]);
    };

    controlRepeatPassword = () => {
        if (this.passwordRepeatField.value !== this.passwordField.value) {
            this.addMessage(this.passwordRepeatField, 'Hasła muszą być takie same', 'form-wrong', 'repeat-password-message');
        } else {
            this.addMessage(this.passwordRepeatField, 'OK!', 'form-ok', 'repeat-password-message');
        }
    };

    controlForm = (e) => {
        e.preventDefault();
        if (document.getElementsByClassName('form-wrong').length === 0) {
            this.form.submit();
        } else {
            alert('Formularz zawiera błędy.');
        }
    };

    addPasswordMessage = (str, className) => {
        const msg = 'Siła hasła: ' + str;
        const fullClassName = 'password-' + className;
        this.addMessage(this.passwordField, msg, fullClassName, 'password-message');
    };

    addMessage = (element, str, className, id) => {
        let messageContainer = document.getElementById(id);
        if (messageContainer) {
            messageContainer.innerText = str;
            messageContainer.className = 'form-message ' + className;
        } else {
            messageContainer = document.createElement('DIV');
            messageContainer.innerText = str;
            messageContainer.className = 'form-message ' + className;
            messageContainer.id = id;
            element.parentNode.appendChild(messageContainer);
        }
    };
}

calculatePasswordStrength = str => {
    if (str.length === 0) {
        return 0;
    }
    const entropy = calculateEntropy(str);
    const adjustedLength = Math.log2(str.length);
    return entropy * adjustedLength;
};

calculateEntropy = str => {
  const set = {};

  str.split('').forEach(
    c => (set[c] ? set[c]++ : (set[c] = 1))
  );

  return Object.keys(set).reduce((acc, c) => {
    const p = set[c] / str.length;
    return acc - (p * (Math.log(p) / Math.log(2)));
  }, 0);
};
