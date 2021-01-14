window.onload = () => {
    const registerController = new RegisterController();
    registerController.setupListeners();
};

class RegisterController extends PasswordController {
    constructor() {
        super();
        this.emailField = document.getElementById('email');
        this.firstNameField = document.getElementById('first-name');
        this.lastNameField = document.getElementById('last-name');
    }

    setupListeners() {
        super.setupListeners();
        this.emailField.addEventListener('keyup', this.controlEmail);
        this.firstNameField.addEventListener('keyup', e => this.controlName(e, 'first-name'));
        this.lastNameField.addEventListener('keyup', e => this.controlName(e, 'last-name'));
    }

    controlEmail = () => {
        const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        if (re.test(String(this.emailField.value).toLowerCase())) {
            this.addMessage(this.emailField, 'OK!', 'form-ok', 'email-message');
        } else {
            this.addMessage(this.emailField, 'Niepoprawny adres email', 'form-wrong', 'email-message');
        }
    };

    controlName = (e, id) => {
        const plUppercase = 'ĄĆĘŁŃÓŚŹŻ';
        const plLowercase = 'ąćęłńóśźż';
        const re = new RegExp(`[A-Z${plUppercase}][a-z${plLowercase}]+`);
        if (e.target.value.match(re)) {
            this.addMessage(e.target, 'OK!', 'form-ok', id + '-message');
        } else {
            this.addMessage(e.target, 'Imię oraz nazwisko muszą rozpoczynać się dużą literą.', 'form-wrong', id + '-message');
        }
    };
};
