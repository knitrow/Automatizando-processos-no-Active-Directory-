# Automatizando-processos-no-Active-Directory-
# Definir o caminho do arquivo com os usuarios
#$arquivo = "C:\UM\CAMINHO\PARA\A\listarusuarios.txt"

# Definir os grupos a serem criados
#$grupos = @("TI", "Comercial", "Financeiro", "Compras", "Producao")

# Criar grupos no Active Directory caso nao existam
<#
foreach ($grupo in $grupos) {
    if (-not (Get-ADGroup -Filter {Name -eq $grupo})) {
        New-ADGroup -Name $grupo -GroupScope Global -GroupCategory Security -Description "Grupo $grupo"
    }
}
#>

#$i = 0 # Contador de linha

# Ler o arquivo de usuarios e criar no AD
<#
Get-Content $arquivo | ForEach-Object {
    # Separar dados do usuario (nome.sobrenome)
    $dados = $_ -split ";"
    $usuario = $dados[0]
    $departamento = $dados[1]

    # Criar nome e definir credenciais
    $nomeCompleto = $usuario
    $nome = $usuario.Split("_")[0]
    $sobrenome = $usuario.Split("_")[1]
    $usuarioPrincipal = "$nome.$sobrenome"
    $senha = ConvertTo-SecureString "Senai@134" -AsPlainText -Force

    # Criar usuario no AD
    New-ADUser -SamAccountName $usuarioPrincipal `
               -UserPrincipalName "$usuarioPrincipal@dominio.com" `
               -Name "$nomeCompleto" `
               -GivenName $nome `
               -Surname $sobrenome `
               -DisplayName "$nome $sobrenome" `
               -AccountPassword $senha `
               -Enabled $true `
               -PassThru `
               -ChangePasswordAtLogon $true

    # Atribuir usuario ao grupo correspondente (rodizio)
    $indiceGrupo = $i % $grupos.Length
    $grupoEscolhido = $grupos[$indiceGrupo]
    Add-ADGroupMember -Identity $grupoEscolhido -Members $usuarioPrincipal

    Write-Host "Usuario $usuarioPrincipal criado e adicionado ao grupo $grupoEscolhido"
    
    $i++
}
#>

# Validar criacao e alocacao dos usuarios
<#
$usuariosCriados = Get-ADUser -Filter * -Property MemberOf 
foreach ($usuario in $usuariosCriados) {
    $gruposUsuario = $usuario.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }
    Write-Host "Usuario: $($usuario.SamAccountName) - Grupos: $($gruposUsuario -join ', ')"
}
#>

# Parte 2 - Monitoramento e limpeza de contas inativas
<#
$limite = (Get-Date).AddDays(-90)
$usuariosInativos = Get-ADUser -Filter {LastLogonTimeStamp -lt $limite} -Properties LastLogonTimeStamp | 
                    Select-Object Name, SamAccountName, LastLogonTimeStamp

$usuariosInativos | Export-Csv "C:\UM\CAMINHO\PARA\A\Relatorio_Usuarios_Inativos.csv" -NoTypeInformation

foreach ($usuario in $usuariosInativos) {
    Disable-ADAccount -Identity $usuario.SamAccountName
    Write-Host "Conta desativada: $($usuario.SamAccountName)"
}
#>

# Parte 3 - Desabilitação de contas com base em lista do RH
# Define o caminho do arquivo TXT contendo os usuários desligados
$arquivoUsuarios = "C:\UM\CAMINHO\PARA\A\usuariosdesativados.txt"

# Define o caminho do log e cria o arquivo se não existir
$logPath = "C:\UM\CAMINHO\PARA\A\Log_Desativacao.txt"
if (!(Test-Path $logPath)) { New-Item -Path $logPath -ItemType File -Force }

# Verifica se o arquivo de usuários desligados existe
if (Test-Path $arquivoUsuarios) {
    # Lê todas as linhas do arquivo TXT
    $listaUsuarios = Get-Content $arquivoUsuarios

    foreach ($linha in $listaUsuarios) {
        $usuariodis = $linha.Trim()  # Remove espaços extras

        # Verifica se a linha não está vazia
        if (![string]::IsNullOrWhiteSpace($usuariodis)) {
            # Procura o usuário no Active Directory
            $usuarioAD = Get-ADUser -Filter {SamAccountName -eq $usuariodis} -Properties Enabled

            if ($usuarioAD) {
                if ($usuarioAD.Enabled) {
                    Disable-ADAccount -Identity $usuariodis
                    Add-Content -Path $logPath -Value "Usuário desativado: $usuariodis"
                    Write-Host "Usuário $usuariodis desativado."
                } else {
                    Write-Host "Usuário $usuariodis já está desativado."
                }
            } else {
                Add-Content -Path $logPath -Value "Usuário não encontrado: $usuariodis"
                Write-Host "Usuário $usuariodis não encontrado no AD."
            }
        } else {
            Write-Host "Linha inválida no TXT (usuário vazio)."
        }
    }
} else {
    Write-Host "Erro: O arquivo $arquivoUsuarios não foi encontrado."
}
