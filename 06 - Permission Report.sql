SET NOCOUNT ON;
---------------------------------------------------------------------------------------------------------


---------------------------------------------------------------------------------------------------------

DECLARE @username VARCHAR(100) = '%%'--@jbknowledge.com'
DECLARE @rolename VARCHAR(100) = '%%'
DECLARE @object VARCHAR(100) = '%%'

-- LIST USERS -------------------------------------------------------------------------------------------

SELECT [name] AS [User name],
       [type_desc] AS [User Type],
       FORMAT([create_date], 'yyyy-MM-dd  hh:mm:ss') AS [Create Date],
	   [Create] = CASE [type_desc]
                      WHEN 'EXTERNAL_USER' THEN
                          'CREATE USER [' + [name] + '] FROM EXTERNAL PROVIDER WITH DEFAULT_SCHEMA = dbo;'
                      WHEN 'EXTERNAL_GROUP' THEN
                          'CREATE USER [' + [name] + '] FROM EXTERNAL PROVIDER WITH DEFAULT_SCHEMA = dbo;'
                      WHEN 'SQL_USER' THEN
                          'CREATE USER [' + [name] + '] WITH PASSWORD = ''*******'''
					  ELSE
					      NULL
                  END,
       'DROP USER [' + [name] + ']' AS [Drop]
FROM sys.database_principals
WHERE type IN ( 'E', 'X', 'S' )
      AND sid IS NOT NULL
      AND name <> 'guest'
      AND name <> 'dbo'
      AND name LIKE @username
ORDER BY [name];

-- 'A' = Application role
-- 'C' = User mapped to a certificate
-- 'E' = External user from Azure Active Directory
-- 'G' = Windows group
-- 'K' = User mapped to an asymmetric key
-- 'R' = Database role
-- 'S' = SQL user
-- 'U' = Windows user
-- 'X' = External group from Azure Active Directory group or applications

-- LIST USERS ROLES -------------------------------------------------------------------------------------

SELECT m.name AS [User name],
       r.name [Role name],
       FORMAT(m.[create_date], 'yyyy-MM-dd  hh:mm:ss') AS [Create Date],
	   'ALTER ROLE ' + r.name + ' ADD MEMBER [' + m.name + ']' AS [Grant],
       'ALTER ROLE ' + r.name + ' DROP MEMBER [' + m.name + ']' AS [Revoke]
FROM sys.database_role_members rm
    JOIN sys.database_principals r
        ON rm.role_principal_id = r.principal_id
    JOIN sys.database_principals m
        ON rm.member_principal_id = m.principal_id
WHERE r.type = 'R'
      AND m.name <> 'dbo'
      AND m.name LIKE @username
      AND r.name LIKE @rolename
ORDER BY m.name;

-- LIST USERS PERMISSIONS

SELECT pri.name AS [User name],
       permit.permission_name AS [Permission],
       permit.class_desc AS [Class Name],
       [Object Name] = CASE permit.class_desc
                           WHEN 'OBJECT_OR_COLUMN' THEN
                               OBJECT_NAME(permit.major_id)
                           WHEN 'SCHEMA' THEN
                               SCHEMA_NAME(permit.major_id)
						   ELSE
							   NULL
                       END,
       FORMAT(pri.[create_date], 'yyyy-MM-dd  hh:mm:ss') AS [Create Date],
	   [Grant] = CASE permit.class_desc
                     WHEN 'DATABASE' THEN
                         'GRANT ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' TO ['
                         + pri.name COLLATE DATABASE_DEFAULT + ']'
                     WHEN 'SCHEMA' THEN
                         'GRANT ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' ON SCHEMA::'
                         + SCHEMA_NAME(permit.major_id)COLLATE DATABASE_DEFAULT + ' TO ['
                         + pri.name COLLATE DATABASE_DEFAULT + ']'
                     WHEN 'OBJECT_OR_COLUMN' THEN
                         'GRANT ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' ON '
                         + OBJECT_NAME(permit.major_id)COLLATE DATABASE_DEFAULT + ' TO ['
                         + pri.name COLLATE DATABASE_DEFAULT + ']'
					 ELSE
					     NULL
                 END,
       [Revoke] = CASE permit.class_desc
                      WHEN 'DATABASE' THEN
                          'REVOKE ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' TO ['
                          + pri.name COLLATE DATABASE_DEFAULT + ']'
                      WHEN 'SCHEMA' THEN
                          'REVOKE ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' ON SCHEMA::'
                          + SCHEMA_NAME(permit.major_id)COLLATE DATABASE_DEFAULT + ' TO ['
                          + pri.name COLLATE DATABASE_DEFAULT + ']'
                      WHEN 'OBJECT_OR_COLUMN' THEN
                          'REVOKE ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' ON '
                          + OBJECT_NAME(permit.major_id)COLLATE DATABASE_DEFAULT + ' TO ['
                          + pri.name COLLATE DATABASE_DEFAULT + ']'
				      ELSE
						  NULL
                  END
FROM sys.database_principals pri
    LEFT JOIN sys.database_permissions permit
        ON permit.grantee_principal_id = pri.principal_id
WHERE pri.type_desc <> 'DATABASE_ROLE'
      AND pri.name NOT IN ( 'dbo', 'guest', 'INFORMATION_SCHEMA', 'sys' )
      AND permit.permission_name <> 'CONNECT'
      AND pri.name LIKE @username
ORDER BY pri.name,
         permit.permission_name,
         [Object Name];

-- LIST ROLES PERMISSIONS

SELECT pri.name AS [User name],
       permit.permission_name AS [Permission],
       permit.class_desc AS [Class Name],
       [Object Name] = CASE permit.class_desc
                           WHEN 'OBJECT_OR_COLUMN' THEN
                               OBJECT_NAME(permit.major_id)
                           WHEN 'SCHEMA' THEN
                               SCHEMA_NAME(permit.major_id)
						   ELSE
							   NULL
                       END,
       FORMAT(pri.[create_date], 'yyyy-MM-dd  hh:mm:ss') AS [Create Date],
	   [Grant] = CASE permit.class_desc
                     WHEN 'DATABASE' THEN
                         'GRANT ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' TO ['
                         + pri.name COLLATE DATABASE_DEFAULT + ']'
                     WHEN 'SCHEMA' THEN
                         'GRANT ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' ON SCHEMA::'
                         + SCHEMA_NAME(permit.major_id)COLLATE DATABASE_DEFAULT + ' TO ['
                         + pri.name COLLATE DATABASE_DEFAULT + ']'
                     WHEN 'OBJECT_OR_COLUMN' THEN
                         'GRANT ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' ON '
                         + OBJECT_NAME(permit.major_id)COLLATE DATABASE_DEFAULT + ' TO ['
                         + pri.name COLLATE DATABASE_DEFAULT + ']'
					 ELSE
						 NULL
                 END,
       [Revoke] = CASE permit.class_desc
                      WHEN 'DATABASE' THEN
                          'REVOKE ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' TO ['
                          + pri.name COLLATE DATABASE_DEFAULT + ']'
                      WHEN 'SCHEMA' THEN
                          'REVOKE ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' ON SCHEMA::'
                          + SCHEMA_NAME(permit.major_id)COLLATE DATABASE_DEFAULT + ' TO ['
                          + pri.name COLLATE DATABASE_DEFAULT + ']'
                      WHEN 'OBJECT_OR_COLUMN' THEN
                          'REVOKE ' + permit.permission_name COLLATE DATABASE_DEFAULT + ' ON '
                          + OBJECT_NAME(permit.major_id)COLLATE DATABASE_DEFAULT + ' TO ['
                          + pri.name COLLATE DATABASE_DEFAULT + ']'
					  ELSE
						  NULL
                  END
FROM sys.database_principals pri
    LEFT JOIN sys.database_permissions permit
        ON permit.grantee_principal_id = pri.principal_id
WHERE pri.type_desc = 'DATABASE_ROLE'
      AND pri.name <> 'public'
      AND pri.name NOT IN ( 'dbo', 'guest', 'INFORMATION_SCHEMA', 'sys' )
      AND permit.permission_name <> 'CONNECT'
      AND pri.name LIKE @username
ORDER BY pri.name,
         permit.permission_name,
         [Object Name];

-- GRANT ROLES

PRINT '-- USERS ---------------------------------------------------------------------------------------';
PRINT '';
PRINT 'CREATE USER [' + @username + '] FROM EXTERNAL PROVIDER WITH DEFAULT_SCHEMA = dbo;';
PRINT 'CREATE USER [' + @username + '] WITH PASSWORD = ''*******'';';
PRINT 'ALTER USER [' + @username + '] WITH PASSWORD = ''*******''';
PRINT '';
PRINT '-- LOGINS ---------------------------------------------------------------------------------------';
PRINT '';
PRINT 'CREATE LOGIN [' + @username + '] FROM EXTERNAL PROVIDER';
PRINT 'CREATE LOGIN [' + @username + '] WITH PASSWORD = ''*******''';
PRINT '';
PRINT '-- DATABASE ROLES ---------------------------------------------------------------------------------------';
PRINT '';
PRINT 'ALTER ROLE db_unmask ADD MEMBER [' + @username + ']';
PRINT 'ALTER ROLE db_datareader ADD MEMBER [' + @username + ']';
PRINT 'ALTER ROLE db_datawriter ADD MEMBER [' + @username + ']';
PRINT 'ALTER ROLE db_executor ADD MEMBER [' + @username + ']';
PRINT 'ALTER ROLE db_ddladmin ADD MEMBER [' + @username + ']';
PRINT 'ALTER ROLE db_profiler ADD MEMBER [' + @username + ']';
PRINT 'ALTER ROLE db_owner ADD MEMBER [' + @username + ']';
PRINT '';
PRINT '-- SERVER ROLES ---------------------------------------------------------------------------------------';
PRINT '';
PRINT 'ALTER SERVER ROLE ##MS_DatabaseConnector## ADD MEMBER [' + @username + ']';
PRINT 'ALTER SERVER ROLE ##MS_DatabaseManager## ADD MEMBER [' + @username + ']';
PRINT 'ALTER SERVER ROLE ##MS_DefinitionReader## ADD MEMBER [' + @username + ']';
PRINT 'ALTER SERVER ROLE ##MS_LoginManager## ADD MEMBER [' + @username + ']';
PRINT 'ALTER SERVER ROLE ##MS_SecurityDefinitionReader## ADD MEMBER [' + @username + ']';
PRINT 'ALTER SERVER ROLE ##MS_ServerStateReader## ADD MEMBER [' + @username + ']';
PRINT 'ALTER SERVER ROLE ##MS_ServerStateManager## ADD MEMBER [' + @username + ']';
PRINT '';
PRINT '-- DATABASE LEVEL PERMISSIONS ----------------------------------------------------------------------------------';
PRINT '';
PRINT 'GRANT ALTER TO [' + @username + ']';
PRINT 'GRANT SHOWPLAN TO [' + @username + ']';
PRINT 'GRANT VIEW DEFINITION TO [' + @username + ']';
PRINT 'GRANT VIEW DATABASE STATE TO [' + @username + ']';
PRINT 'GRANT ALTER ANY EXTERNAL DATA SOURCE TO [' + @username + ']';
PRINT '';
PRINT '-- SCHEMA LEVEL PERMISSIONS ----------------------------------------------------------------------------------';
PRINT '';
PRINT 'GRANT VIEW CHANGE TRACKING ON SCHEMA::dbo TO [' + @username + ']';
PRINT '';
PRINT '-- OBJECT LEVEL PERMISSIONS ----------------------------------------------------------------------------------';
PRINT '';
PRINT 'GRANT SELECT ON [' + @object + '] TO [' + @username + ']';
PRINT 'GRANT INSERT ON [' + @object + '] TO [' + @username + ']';
PRINT 'GRANT UPDATE ON [' + @object + '] TO [' + @username + ']';
PRINT 'GRANT DELETE ON [' + @object + '] TO [' + @username + ']';
PRINT 'GRANT EXECUTE ON [' + @object + '] TO [' + @username + ']';
