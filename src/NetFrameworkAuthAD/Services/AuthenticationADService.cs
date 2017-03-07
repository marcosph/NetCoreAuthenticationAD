

using System;
using System.DirectoryServices.AccountManagement;

namespace NetFrameworkAuthAD.Services
{
    public class AuthenticationADService
    {
        public class AuthenticationResult
        {
            public AuthenticationResult(string errorMessage = null)
            {
                ErrorMessage = errorMessage;
            }

            public String ErrorMessage { get; private set; }
            public Boolean IsSuccess => String.IsNullOrEmpty(ErrorMessage);
        }

        /// <summary>
        /// Verificar se login e senha existe no AD. 
        /// </summary>
        /// <param name="login"></param>
        /// <param name="senha"></param>
        /// <returns></returns>
        public AuthenticationResult SignIn(string login, string senha)
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


    }
}
