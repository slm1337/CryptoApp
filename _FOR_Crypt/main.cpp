#include <iostream>
#include <locale>
#include <string>
#include <windows.h>
#include <fstream>
#include <codecvt>
#include <vector>
#include <algorithm>
#include <memory>

using namespace std;

class EncryptionStrategy {
protected:
    const wstring alphabet = L"абвгдеёжзийклмнопрстуфхцчшщъыьэюя ,.!?-:\"–";

public:
    virtual wstring encrypt(const wstring& text) const = 0;
    virtual wstring decrypt(const wstring& text) const = 0;
    virtual ~EncryptionStrategy() = default;
};

class CaesarCipher : public EncryptionStrategy {
public:
    wstring encrypt(const wstring& text) const override {
        return shift(text, 3);
    }

    wstring decrypt(const wstring& text) const override {
        return shift(text, -3);
    }

private:
    wstring shift(const wstring& text, int shift) const {
        wstring result = text;

        for (wchar_t& ch : result) {
            size_t index = alphabet.find(ch);
            if (index != wstring::npos) {
                index = (index + shift + alphabet.size()) % alphabet.size();
                ch = alphabet[index];
            }
        }

        return result;
    }
};

class TrithemiusCipher : public EncryptionStrategy {
public:
    wstring encrypt(const wstring& text) const override {
        return shift(text, true);
    }

    wstring decrypt(const wstring& text) const override {
        return shift(text, false);
    }

private:
    wstring shift(const wstring& text, bool encrypt) const {
        wstring result;
        int alphabetSize = alphabet.size();

        for (int i = 0; i < text.size(); ++i) {
            wchar_t currentChar = text[i];
            wstring shiftedAlphabet = alphabet;

            if (encrypt) {
                rotate(shiftedAlphabet.begin(), shiftedAlphabet.begin() + i % alphabetSize, shiftedAlphabet.end());
            }
            else {
                rotate(shiftedAlphabet.rbegin(), shiftedAlphabet.rbegin() + i % alphabetSize, shiftedAlphabet.rend());
            }

            auto pos = find(alphabet.begin(), alphabet.end(), currentChar);

            if (pos != alphabet.end()) {
                int charPos = distance(alphabet.begin(), pos);
                wchar_t resultChar = shiftedAlphabet[charPos];
                result.push_back(resultChar);
            }
            else {
                result.push_back(currentChar);
            }
        }

        return result;
    }
};

class VigenereCipher : public EncryptionStrategy {
private:
    const wstring key;

public:
    VigenereCipher(const wstring& key) : key(key) {}

    wstring encrypt(const wstring& text) const override {
        return process(text, true);
    }

    wstring decrypt(const wstring& text) const override {
        return process(text, false);
    }

private:
    wstring process(const wstring& text, bool isEncrypt) const {
        const int alphabetSize = alphabet.size();
        wstring resultText = L"";

        size_t keyIndex = 0;
        for (size_t i = 0; i < text.size(); ++i) {
            wchar_t textChar = text[i];
            wchar_t keyChar = key[keyIndex++ % key.size()];

            int textIndex = alphabet.find(textChar);
            int keyIndex = alphabet.find(keyChar);

            int resultIndex;
            if (isEncrypt) {
                resultIndex = (textIndex + keyIndex + 1) % alphabetSize;
            }
            else {
                resultIndex = (textIndex - keyIndex - 1 + alphabetSize) % alphabetSize;
                if (resultIndex < 0) {
                    resultIndex += alphabetSize;
                }
            }

            resultText += alphabet[resultIndex];
        }

        return resultText;
    }
};

class GammaCipher : public EncryptionStrategy {
private:
    const wstring key;

public:
    GammaCipher(const wstring& key) : key(key) {}

    wstring encrypt(const wstring& text) const override {
        return process(text);
    }

    wstring decrypt(const wstring& text) const override {
        return process(text); // XOR encryption and decryption are the same operation
    }

private:
    wstring process(const wstring& text) const {
        wstring result = text;
        for (size_t i = 0; i < text.size(); ++i) {
            result[i] = text[i] ^ key[i % key.size()];
        }
        return result;
    }
};

class Encryptor {
private:
    unique_ptr<EncryptionStrategy> strategy;

public:
    void setStrategy(unique_ptr<EncryptionStrategy> newStrategy) {
        strategy = move(newStrategy);
    }

    wstring encrypt(const wstring& text) const {
        return strategy->encrypt(text);
    }

    wstring decrypt(const wstring& text) const {
        return strategy->decrypt(text);
    }
};

class FileProcessor {
public:
    static wstring ReadFile(const wstring& fileName) {
        wifstream file(fileName, ios::binary);
        wstring content;

        if (file.is_open()) {
            file.imbue(locale(locale(), new codecvt_utf8<wchar_t>));
            content.assign((istreambuf_iterator<wchar_t>(file)), istreambuf_iterator<wchar_t>());
            file.close();
        }

        return content;
    }

    static void WriteFile(const wstring& fileName, const wstring& content) {
        wofstream file(fileName, ios::binary | ios::trunc);

        if (file.is_open()) {
            file.imbue(locale(locale(), new codecvt_utf8<wchar_t>));
            file << content;
            file.close();
        }
    }
};

wstring GetOpenFileNameDialog() {
    OPENFILENAME ofn;
    wchar_t fileName[MAX_PATH] = L"\0";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = L"Текстовые файлы (*.txt)\0*.txt\0Все файлы (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE) {
        return fileName;
    }
    else {
        return L"";
    }
}

wstring GetSaveFileNameDialog() {
    OPENFILENAME ofn;
    wchar_t fileName[MAX_PATH] = L"\0";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = L"Текстовые файлы (*.txt)\0*.txt\0Все файлы (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (GetSaveFileName(&ofn) == TRUE) {
        return fileName;
    }
    else {
        return L"";
    }
}

wstring GetPassword(const wstring& prompt) {
    wcout << prompt;

    wchar_t password[26];
    int index = 0;

    while (true) {
        wchar_t ch = _getwch();

        if (ch == 13) {  // Enter key
            break;
        }
        else if (ch == 8) {  // Backspace key
            if (index > 0) {
                --index;
                wcout << "\b \b";
            }
        }
        else if (index < 25 && iswprint(ch)) {
            password[index++] = ch;
            wcout << L'*';
        }
    }

    password[index] = L'\0';
    wcout << endl;

    return password;
}

int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
    SetConsoleOutputCP(CP_UTF8);

    int repeat;
    do {
        std::wcout << L"Выберите input файл" << std::endl;
        wstring inputFileName = GetOpenFileNameDialog();
        std::wcout << L"Выберите output файл \n" << std::endl;
        wstring outputFileName = GetSaveFileNameDialog();

        if (inputFileName.empty() || outputFileName.empty()) {
            wcerr << L"Выбор файлов отменен." << endl;
            return 0;
        }

        int action;
        do {
            wcout << L"Выберите метод шифрования:" << endl;
            wcout << L"1. Шифр Цезаря" << endl;
            wcout << L"2. Модифицированный шифр Цезаря(шифр Тритемиуса)" << endl;
            wcout << L"3. Гаммирование" << endl;
            wcout << L"4. Шифр Виженера\n" << endl;
            wcout << L"Ваш выбор: ";
            wcin >> action;

            if (action < 1 || action > 4) {
                wcout << L"\nНеверный выбор метода шифрования. Повторите ввод.\n" << endl;
            }
        } while (action < 1 || action > 4);

        wcout << endl;
        wstring password = GetPassword(L"Введите пароль: ");
        wstring confirmPassword = GetPassword(L"Подтвердите пароль: ");

        while (password != confirmPassword) {
            wcout << L"\nПароли не совпадают. Повторите ввод.\n" << endl;
            password = GetPassword(L"Введите пароль: ");
            confirmPassword = GetPassword(L"Подтвердите пароль: ");
        }

        wcout << L"\nПароль принят.\n" << endl;
        wstring key = password;

        Encryptor encryptor;
        switch (action) {
        case 1:
            encryptor.setStrategy(make_unique<CaesarCipher>());
            break;
        case 2:
            encryptor.setStrategy(make_unique<TrithemiusCipher>());
            break;
        case 3:
            encryptor.setStrategy(make_unique<GammaCipher>(key));
            break;
        case 4:
            encryptor.setStrategy(make_unique<VigenereCipher>(key));
            break;
        default:
            wcerr << L"Неверный выбор метода шифрования." << endl;
            return 0;
        }

        int encryptAction;
        do {
            wcout << L"Выберите действие:" << endl;
            wcout << L"1. Зашифровать" << endl;
            wcout << L"2. Расшифровать\n" << endl;
            wcout << L"Ваш выбор: ";
            wcin >> encryptAction;

            if (encryptAction != 1 && encryptAction != 2) {
                wcout << L"\nНеверный выбор. Повторите ввод.\n" << endl;
            }
        } while (encryptAction != 1 && encryptAction != 2);

        wstring content = FileProcessor::ReadFile(inputFileName);
        if (encryptAction == 1) {
            content = encryptor.encrypt(content);
        }
        else {
            content = encryptor.decrypt(content);
        }
        FileProcessor::WriteFile(outputFileName, content);

        do {
            wcout << L"Хотите повторить процесс шифрования/дешифрования? (1 - да, 0 - нет): ";
            wcin >> repeat;
            wcout << endl;
            if (repeat != 1 && repeat != 0) {
                wcout << L"Неверный выбор. Повторите ввод.\n" << endl;
            }
        } while (repeat != 1 && repeat != 0);
    } while (repeat == 1);

    return 0;
}