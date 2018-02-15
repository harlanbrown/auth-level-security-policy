/*
 * Copyright (c) 2006-2018 Nuxeo SA (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Harlan Brown
 */

package org.nuxeo.sample;

import java.security.Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.core.api.security.Access;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.query.sql.model.Expression;
import org.nuxeo.ecm.core.query.sql.model.LiteralList;
import org.nuxeo.ecm.core.query.sql.model.Operator;
import org.nuxeo.ecm.core.query.sql.model.Predicate;
import org.nuxeo.ecm.core.query.sql.model.Reference;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery.Transformer;
import org.nuxeo.ecm.core.query.sql.model.StringLiteral;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery;
import org.nuxeo.ecm.core.query.sql.model.WhereClause;
import org.nuxeo.ecm.core.security.AbstractSecurityPolicy;
import org.nuxeo.ecm.core.security.SecurityPolicy;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;

public class AuthLevelSecurityPolicy extends AbstractSecurityPolicy implements SecurityPolicy {

    //change this to use schema where auth_level_cde is defined
    public static final String AUTH_LEVEL_FIELD = "file_schema:auth_level_cde";
    
    public static final String RIGHTS_DEFAULT = "MCD_DEFAULT";
    public static final String RIGHTS_GROUP1 = "MCD_HOONLY";
    public static final String RIGHTS_GROUP2 = "MCD_HOFLD";
    public static final String RIGHTS_GROUP3 = "MCD_HOCLNT";

    public static final String PRINCIPAL_GROUP1 = "ACA-HO";
    public static final String PRINCIPAL_GROUP2 = "ACA-FR";
    public static final String PRINCIPAL_GROUP3 = "ACA-CLNT";
    
    private static final Log log = LogFactory.getLog(AuthLevelSecurityPolicy.class);

    @Override
    public Access checkPermission(Document doc, ACP mergedAcp, Principal principal, String permission,
            String[] resolvedPermissions, String[] additionalPrincipals) {
    	NuxeoPrincipal p = (NuxeoPrincipal) principal;
    	/*
 *  If the document has the auth_level_cde value below 
 *  AND the principal is in the corresponding group
 *  GRANT permission
        *******************************************************************
        *  auth_level_cde Metadata Field  *  Username in Nuxeo User Group *
        *******************************************************************
        *             MCD_DEFAULT         *             ACA-HO            *
        *******************************************************************
        *             MCD_HOONLY          *             ACA-HO            *
        *******************************************************************
        *             MCD_HOFLD           *             ACA-FR            *
        *******************************************************************
        *             MCD_HOCLNT          *             ACA-CLNT          *
        *******************************************************************
*/
        String rights = (String) doc.getPropertyValue(AUTH_LEVEL_FIELD);

        if ( rights != null ) {
            
        	if (rights.equals(RIGHTS_DEFAULT)) {
        		if (p.isMemberOf(PRINCIPAL_GROUP1)) {
        			log.trace(String.format("Returning access %s for user %s on document %s", Access.GRANT, p, doc));
        			return Access.GRANT;
        		} else {
        			log.trace(String.format("Returning access %s for user %s on document %s", Access.DENY, p, doc));
        			return Access.DENY;
        		}           
        	} 
            
            if (rights.equals(RIGHTS_GROUP1)) {
        		if (p.isMemberOf(PRINCIPAL_GROUP1)) {
        			log.trace(String.format("Returning access %s for user %s on document %s", Access.GRANT, p, doc));
        			return Access.GRANT;
        		} else {
        			log.trace(String.format("Returning access %s for user %s on document %s", Access.DENY, p, doc));
        			return Access.DENY;
        		}            	
            }
            if (rights.equals(RIGHTS_GROUP2)) {
        		if (p.isMemberOf(PRINCIPAL_GROUP2)) {
        			log.trace(String.format("Returning access %s for user %s on document %s", Access.GRANT, p, doc));
        			return Access.GRANT;
        		} else {
        			log.trace(String.format("Returning access %s for user %s on document %s", Access.DENY, p, doc));
        			return Access.DENY;
        		}           
            }
            if (rights.equals(RIGHTS_GROUP3)) {
        		if (p.isMemberOf(PRINCIPAL_GROUP3)) {
        			log.trace(String.format("Returning access %s for user %s on document %s", Access.GRANT, p, doc));
        			return Access.GRANT;
        		} else {
        			log.trace(String.format("Returning access %s for user %s on document %s", Access.DENY, p, doc));
        			return Access.DENY;
        		}           
            }
        }
		log.trace(String.format("Returning access %s for user %s on document %s", Access.UNKNOWN, p, doc));
        return Access.UNKNOWN;
        
    }

    @Override
    public boolean isRestrictingPermission(String permission) {
        return false;
    }

    @Override
    public boolean isExpressibleInQuery(String repositoryName) {
        return true;
    }

    public static class AuthLevelTransformer implements Transformer {

        private static final long serialVersionUID = 1L;

        // A SQL Query is made whenever a document listing is shown
        // This transformer changes the SQL query so that restricted documents are not shown in results
        @Override
        public SQLQuery transform(Principal principal, SQLQuery query) {
        	
        	UserManager userManager = Framework.getService(UserManager.class);
        	// cannot get groups from incoming principal object, need to fetch a NuxeoPrincipalImpl from user manager
        	NuxeoPrincipal p = userManager.getPrincipal(principal.getName());
        	
            WhereClause where = query.where;
            Predicate predicate = null;
            
            // if user is system or Admin do nothing
            if (principal.getName().equals("system") || principal.getName().equals("Administrator")){
                return query;
            }
            
        	// if principal in group 1 return query checking if field = default
        	if (p.isMemberOf(PRINCIPAL_GROUP1)) {
        		// AND (auth_level_cde IS NULL OR dc:rights IN ('DEFAULT','GROUP1'))
        		Expression expr = new Expression(new Reference(AUTH_LEVEL_FIELD), Operator.ISNULL, null);
                LiteralList list = new LiteralList();
                list.add(new StringLiteral(RIGHTS_DEFAULT));
                list.add(new StringLiteral(RIGHTS_GROUP1));
        		Expression expr2 = new Expression(new Reference(AUTH_LEVEL_FIELD), Operator.IN, list);
        		predicate = new Predicate(expr, Operator.OR, expr2);
        	}       	
        	// if principal in group 2 return query checking if field = group2
        	else if (p.isMemberOf(PRINCIPAL_GROUP2)) {
        		// AND (auth_level_cde IS NULL OR dc:rights = 'GROUP2')
        		Expression expr = new Expression(new Reference(AUTH_LEVEL_FIELD), Operator.ISNULL, null);
        		Expression expr2 = new Expression(new Reference(AUTH_LEVEL_FIELD), Operator.EQ, new StringLiteral(RIGHTS_GROUP2));
        		predicate = new Predicate(expr, Operator.OR, expr2);
        	}
        	// if principal in group 3 return query checking if field = group3
        	else if (p.isMemberOf(PRINCIPAL_GROUP3)) {
        		// AND (auth_level_cde IS NULL OR dc:rights = 'GROUP3')
        		Expression expr = new Expression(new Reference(AUTH_LEVEL_FIELD), Operator.ISNULL, null);
        		Expression expr2 = new Expression(new Reference(AUTH_LEVEL_FIELD), Operator.EQ, new StringLiteral(RIGHTS_GROUP3));
        		predicate = new Predicate(expr, Operator.OR, expr2);
        	} 
        	else {
        		return query;
        	}

            // a sql query can have a WHERE clause or not have a WHERE clause
            // if it does not have a WHERE clause we add our new predicate using WHERE
            // if it already has a WHERE clause we add our predicate to it

            if (where == null || where.predicate == null) {
                return new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy, query.having, query.orderBy, query.limit, query.offset);
            } else {
            	predicate = new Predicate(where.predicate, Operator.AND, predicate);
                return new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy, query.having, query.orderBy, query.limit, query.offset);
            }
        }
    }

    public static final Transformer AUTH_LEVEL_TRANSFORMER = new AuthLevelTransformer();

    @Override
    public Transformer getQueryTransformer(String repositoryName) {
        return AUTH_LEVEL_TRANSFORMER;
    }

}
