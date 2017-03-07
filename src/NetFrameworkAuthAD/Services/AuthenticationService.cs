using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Threading.Tasks;

namespace NetFrameworkAuthAD.Services
{
    public interface IAuthenticationService
    {
        AuthenticationResult SignIn(string login, string senha);
        InfoUsuarioAD GetInfoUsuarioAD(string username);
        string GetUserEmail(string username);
        string GetFullNameAD(string username);
    }
    public class AuthenticationService : IAuthenticationService
    {
        public  AuthenticationResult SignIn(string login, string senha)
        {
            #if DEBUG
            // autentica sua máquina local - para o time de desenvolvedores
            ContextType authenticationType = ContextType.Machine;
            #else
            // autentica seu Domain AD
            ContextType authenticationType = ContextType.Domain;
            #endif

            PrincipalContext principalContext = new PrincipalContext(authenticationType);
            bool isAuthenticated = false;
            UserPrincipal userPrincipal = null;
            try
            {
                isAuthenticated = principalContext.ValidateCredentials(login, senha, ContextOptions.Negotiate);
                if (isAuthenticated)
                {
                    userPrincipal = UserPrincipal.FindByIdentity(principalContext, login);
                }
            }
            catch (Exception)
            {
                isAuthenticated = false;
                userPrincipal = null;
            }
            if (!isAuthenticated || userPrincipal == null)
            {
                return new AuthenticationResult("Login ou Senha está incorreto");
            }
            if (userPrincipal.IsAccountLockedOut())
            {
                return new AuthenticationResult("Sua conta está bloqueada.");
            }
            if (userPrincipal.Enabled.HasValue && userPrincipal.Enabled.Value == false)
            {
                return new AuthenticationResult("Sua conta está desabilitada");
            }
            return new AuthenticationResult();
        }
        public string GetUserEmail(string username)
        {
            #if DEBUG
                 // autentica sua máquina local - para o time de desenvolvedores
                 ContextType authenticationType = ContextType.Machine;
            #else
                // autentica seu Domain AD
                ContextType authenticationType = ContextType.Domain;
            #endif
            UserPrincipal userPrincipal = null;
            PrincipalContext principalContext = new PrincipalContext(authenticationType);
            userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);
            if (string.IsNullOrEmpty(userPrincipal.EmailAddress))
            {
                return "";
            }
            else
            {
                return userPrincipal.EmailAddress;
            }
        }

        public string GetFullNameAD(string username)
        {
           #if DEBUG
            // autentica sua máquina local - para o time de desenvolvedores
            ContextType authenticationType = ContextType.Machine;
           #else
                        // autentica seu Domain AD
                        ContextType authenticationType = ContextType.Domain;
           #endif

            UserPrincipal userPrincipal = null;
            PrincipalContext principalContext = new PrincipalContext(authenticationType);
            userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);
            if (string.IsNullOrEmpty(userPrincipal.DisplayName))
            {
                return "";
            }
            else
            {
                return userPrincipal.DisplayName;
            }
        }

        public InfoUsuarioAD GetInfoUsuarioAD(string username)
        {
            var infoUser = new InfoUsuarioAD();

            #if DEBUG
               // autentica sua máquina local - para o time de desenvolvedores
               ContextType authenticationType = ContextType.Machine;
            #else
                // autentica seu Domain AD
                ContextType authenticationType = ContextType.Domain;
            #endif
            UserPrincipal userPrincipal = null;
            PrincipalContext principalContext = new PrincipalContext(authenticationType);
            userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);

            infoUser.Email = string.IsNullOrEmpty(userPrincipal.EmailAddress) ? "" : userPrincipal.EmailAddress;
            infoUser.Nome = string.IsNullOrEmpty(userPrincipal.DisplayName) ? "" : userPrincipal.DisplayName;
                       
            return infoUser;
        }
    }

    public class AuthenticationResult
    {
        public AuthenticationResult(string errorMessage = null)
        {
            ErrorMessage = errorMessage;
        }

        public String ErrorMessage { get; private set; }
        public Boolean IsSuccess => String.IsNullOrEmpty(ErrorMessage);
    }

    public class InfoUsuarioAD
    {
        public InfoUsuarioAD(string nome, string email)
        {
            Nome = nome;
            Email = email;
        }  
        public InfoUsuarioAD() { }      

        public string Nome { get; set; }
        public string Email { get; set; }
       
    }
}
