#include "views/LoginView.hpp"
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSignalSpy>
#include <QString>
#include <QTest>
#include <QTimer>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/security/SecureString.hpp"

#include "hepatizon/crypto/ICryptoProvider.hpp"
#include "hepatizon/storage/IStorageRepository.hpp"

#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"

namespace fs = std::filesystem;

class LoginViewTest : public ::testing::Test
{
protected:
    fs::path tempPath;

    std::unique_ptr<hepatizon::crypto::ICryptoProvider> crypto;
    std::unique_ptr<hepatizon::storage::IStorageRepository> storage;
    std::unique_ptr<hepatizon::core::VaultService> service;
    std::unique_ptr<LoginView> view;

    void SetUp() override
    {
        tempPath = fs::temp_directory_path() / ("test_gui_" + std::to_string(std::rand()));
        fs::create_directories(tempPath);

        crypto = hepatizon::crypto::providers::makeNativeCryptoProvider();
        storage = hepatizon::storage::sqlite::makeSqliteStorageRepository();
        service = std::make_unique<hepatizon::core::VaultService>(*crypto, *storage);

        createTestVault("secret123");

        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        view = std::make_unique<LoginView>(*service);
        view->show();
    }

    void TearDown() override
    {
        view.reset();
        service.reset();

        std::error_code ec;
        fs::remove_all(tempPath, ec);
    }

    void createTestVault(const std::string& password)
    {
        auto secPass = hepatizon::security::secureStringFrom(password);
        (void)service->createVault(tempPath, secPass);
    }
};

TEST_F(LoginViewTest, UI_Elements_Are_Present)
{
    auto* pathInput = view->findChild<QLineEdit*>();
    ASSERT_NE(pathInput, nullptr);

    bool foundUnlock = false;
    for (auto* btn : view->findChildren<QPushButton*>())
    {
        if (btn->text().toUpper().contains("UNLOCK"))
        {
            foundUnlock = true;
            break;
        }
    }
    ASSERT_TRUE(foundUnlock);
}

TEST_F(LoginViewTest, Successful_Unlock_Emits_Signal)
{
    auto* pathInput = view->findChild<QLineEdit*>();
    ASSERT_NE(pathInput, nullptr);
    pathInput->setText(QString::fromStdString(tempPath.string()));

    QLineEdit* passInput = nullptr;
    for (auto* le : view->findChildren<QLineEdit*>())
    {
        if (le->echoMode() == QLineEdit::Password)
        {
            passInput = le;
            break;
        }
    }
    ASSERT_NE(passInput, nullptr);

    QPushButton* unlockBtn = nullptr;
    for (auto* btn : view->findChildren<QPushButton*>())
    {
        if (btn->text().toUpper().contains("UNLOCK"))
        {
            unlockBtn = btn;
            break;
        }
    }
    ASSERT_NE(unlockBtn, nullptr);

    QSignalSpy spy(view.get(), &LoginView::vaultUnlocked);

    QTest::keyClicks(passInput, "secret123");
    QTest::mouseClick(unlockBtn, Qt::LeftButton);

    ASSERT_EQ(spy.count(), 1);

    auto args = spy.takeFirst();
    auto path = args.at(1).value<std::filesystem::path>();
    EXPECT_EQ(path, tempPath);
}

TEST_F(LoginViewTest, Wrong_Password_Shows_Error_And_Does_Not_Emit_Signal)
{
    auto* pathInput = view->findChild<QLineEdit*>();
    pathInput->setText(QString::fromStdString(tempPath.string()));

    QLineEdit* passInput = nullptr;
    for (auto* le : view->findChildren<QLineEdit*>())
    {
        if (le->echoMode() == QLineEdit::Password)
        {
            passInput = le;
            break;
        }
    }
    ASSERT_NE(passInput, nullptr);

    QPushButton* unlockBtn = nullptr;
    for (auto* btn : view->findChildren<QPushButton*>())
    {
        if (btn->text().toUpper().contains("UNLOCK"))
        {
            unlockBtn = btn;
            break;
        }
    }
    ASSERT_NE(unlockBtn, nullptr);

    QSignalSpy spy(view.get(), &LoginView::vaultUnlocked);

    QTest::keyClicks(passInput, "WRONG_PASSWORD_123");

    QTimer::singleShot(200,
                       []()
                       {
                           QWidget* modalWidget = QApplication::activeModalWidget();
                           if (modalWidget)
                           {
                               modalWidget->close();
                           }
                       });

    QTest::mouseClick(unlockBtn, Qt::LeftButton);

    ASSERT_EQ(spy.count(), 0) << "Sygnał nie powinien zostać wyemitowany dla błędnego hasła";
}