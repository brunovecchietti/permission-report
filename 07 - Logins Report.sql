SET NOCOUNT ON;
---------------------------------------------------------------------------------------------------------


---------------------------------------------------------------------------------------------------------

DECLARE @loginname VARCHAR(100) = '%%'--@jbknowledge.com'
DECLARE @rolename VARCHAR(100) = '%%'

-- LIST LOGINS -------------------------------------------------------------------------------------

SELECT	name AS [Login Name], 
		type_desc [Login Type], 
		create_date [Create Date],
		[Create] = CASE [type_desc]
                      WHEN 'EXTERNAL_LOGIN' THEN
                          'CREATE LOGIN [' + [name] + '] FROM EXTERNAL PROVIDER'
                      WHEN 'EXTERNAL_GROUP' THEN
                          'CREATE LOGIN [' + [name] + '] FROM EXTERNAL PROVIDER'
                      WHEN 'SQL_USER' THEN
                          'CREATE LOGIN [' + [name] + '] WITH PASSWORD = ''*******'''
					  ELSE
					      NULL
                  END,
       'DROP LOGIN [' + [name] + ']' AS [Drop]
FROM sys.server_principals
WHERE [type] IN ('S','U','G','E','X')
AND name LIKE @loginname

-- LIST LOGINS ROLES -------------------------------------------------------------------------------------

SELECT
    sp.name AS LoginName,
    sp2.name AS ServerRole,
	'ALTER SERVER ROLE ' + sp2.name + ' ADD MEMBER [' + sp.name + ']' AS [Grant],
    'ALTER SERVER ROLE ' + sp2.name + ' DROP MEMBER [' + sp.name + ']' AS [Revoke]
FROM sys.server_role_members srm
LEFT JOIN sys.server_principals sp ON sp.principal_id = srm.member_principal_id
LEFT JOIN sys.server_principals sp2 ON srm.role_principal_id = sp2.principal_id
WHERE sp.name LIKE @loginname
  AND sp2.name LIKE @rolename


PRINT '-- LOGINS ---------------------------------------------------------------------------------------';
PRINT '';
PRINT 'CREATE LOGIN [' + @loginname + '] FROM EXTERNAL PROVIDER';
PRINT 'CREATE LOGIN [' + @loginname + '] WITH PASSWORD = ''*******''';
PRINT '';
PRINT '-- SERVER ROLES ---------------------------------------------------------------------------------------';
PRINT '';
PRINT 'ALTER SERVER ROLE ##MS_DatabaseConnector## ADD MEMBER [' + @loginname + ']';
PRINT 'ALTER SERVER ROLE ##MS_DatabaseManager## ADD MEMBER [' + @loginname + ']';
PRINT 'ALTER SERVER ROLE ##MS_DefinitionReader## ADD MEMBER [' + @loginname + ']';
PRINT 'ALTER SERVER ROLE ##MS_LoginManager## ADD MEMBER [' + @loginname + ']';
PRINT 'ALTER SERVER ROLE ##MS_SecurityDefinitionReader## ADD MEMBER [' + @loginname + ']';
PRINT 'ALTER SERVER ROLE ##MS_ServerStateReader## ADD MEMBER [' + @loginname + ']';
PRINT 'ALTER SERVER ROLE ##MS_ServerStateManager## ADD MEMBER [' + @loginname + ']';
PRINT '';