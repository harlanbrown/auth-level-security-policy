package org.nuxeo.sample;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import static org.nuxeo.ecm.core.api.security.Access.DENY;
import static org.nuxeo.ecm.core.api.security.Access.GRANT;
import static org.nuxeo.ecm.core.api.security.SecurityConstants.READ;

import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.nuxeo.ecm.core.api.AbstractSession;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.model.Session;
import org.nuxeo.ecm.core.query.sql.SQLQueryParser;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery.Transformer;
import org.nuxeo.ecm.core.security.SecurityPolicyService;
import org.nuxeo.ecm.core.test.CoreFeature;
import org.nuxeo.ecm.platform.test.PlatformFeature;
import org.nuxeo.ecm.core.test.annotations.Granularity;
import org.nuxeo.ecm.core.test.annotations.RepositoryConfig;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.runtime.test.runner.LocalDeploy;
import org.nuxeo.sample.AuthLevelSecurityPolicy.AuthLevelTransformer;
import org.nuxeo.ecm.platform.usermanager.UserManager;

@RunWith(FeaturesRunner.class)
@Features(PlatformFeature.class)
@RepositoryConfig(cleanup = Granularity.METHOD)
@Deploy({
	"org.nuxeo.ecm.platform.content.template"
})
@LocalDeploy({
    "org.nuxeo.sample.securitypolicy:OSGI-INF/security-policy-contrib.xml"
})
public class TestAuthLevelSecurityPolicy {

    @Inject
    protected SecurityPolicyService service;    
    
    @Inject
    protected CoreFeature coreFeature;
    
    @Inject
    protected UserManager userManager;
        
    String id1,id2,id3,id4;
    
    //change this to use schema where auth_level_cde is defined
    public static final String AUTH_LEVEL_FIELD = "file_schema:auth_level_cde";

    public static final String RIGHTS_DEFAULT = "MCD_DEFAULT";
    public static final String RIGHTS_GROUP1 = "MCD_HOONLY";
    public static final String RIGHTS_GROUP2 = "MCD_HOFLD";
    public static final String RIGHTS_GROUP3 = "MCD_HOCLNT";

    public static final String PRINCIPAL_GROUP1 = "ACA-HO";
    public static final String PRINCIPAL_GROUP2 = "ACA-FR";
    public static final String PRINCIPAL_GROUP3 = "ACA-CLNT";
    
    @Before
    public void setUp() {
    	try (CoreSession coreSession = coreFeature.openCoreSession("system")) {
    		
    		DocumentModel ws1 = coreSession.createDocumentModel("/default-domain/workspaces", "ws1", "Workspace");
	    	ws1 = coreSession.createDocument(ws1);
	    	
	    	DocumentModel doc = coreSession.createDocumentModel("/default-domain/workspaces/ws1", "default", "File");
	    	doc.setPropertyValue(AUTH_LEVEL_FIELD, RIGHTS_DEFAULT);
	    	doc = coreSession.createDocument(doc);
	    	id1 = doc.getId();
	    	
	    	DocumentModel doc2 = coreSession.createDocumentModel("/default-domain/workspaces/ws1", "group1", "File");
	    	doc2.setPropertyValue(AUTH_LEVEL_FIELD, RIGHTS_GROUP1);
	    	doc2 = coreSession.createDocument(doc2);
	    	id2 = doc2.getId();
	    	
	    	DocumentModel doc3 = coreSession.createDocumentModel("/default-domain/workspaces/ws1", "group2", "File");
	    	doc3.setPropertyValue(AUTH_LEVEL_FIELD, RIGHTS_GROUP2);
	    	doc3 = coreSession.createDocument(doc3);
	    	id3 = doc3.getId();
	    	
	    	DocumentModel doc4 = coreSession.createDocumentModel("/default-domain/workspaces/ws1", "group3", "File");
	    	doc4.setPropertyValue(AUTH_LEVEL_FIELD, RIGHTS_GROUP3);
	    	doc4 = coreSession.createDocument(doc4);
	    	id4 = doc4.getId();
	    	
	    	coreSession.save();
    	}    	
    }
    
    @Test
    public void testQuery() throws Exception {

    	// user1 should have access to two documents out of the four created in setUp
    	try (CoreSession coreSession = coreFeature.openCoreSession(userManager.getPrincipal("testuser1"))) {
        	assertEquals(2,coreSession.query("SELECT * FROM File").size());
        }
    	// user3 should have access to one document out of the four created in setUp
    	try (CoreSession coreSession = coreFeature.openCoreSession(userManager.getPrincipal("testuser3"))) {
        	assertEquals(1,coreSession.query("SELECT * FROM File").size());
        }
    }
    
    @Test
    public void testCheckPermission() throws Exception {
    	String permission = READ;
        String[] permissions = { READ };

        try (CoreSession coreSession = coreFeature.openCoreSession("testuser1")) {
        	Session documentSession = ((AbstractSession) coreSession).getSession();

        	Document d = documentSession.getDocumentByUUID(id1);
        	assertSame(GRANT, service.checkPermission(d, null, userManager.getPrincipal("testuser1"), permission, permissions, null));
            
        	Document d2 = documentSession.getDocumentByUUID(id2);
        	assertSame(GRANT, service.checkPermission(d2, null, userManager.getPrincipal("testuser1"), permission, permissions, null));
        	
        	Document d3 = documentSession.getDocumentByUUID(id3);
        	assertSame(DENY, service.checkPermission(d3, null, userManager.getPrincipal("testuser1"), permission, permissions, null));
        	
        	Document d4 = documentSession.getDocumentByUUID(id4);
        	assertSame(DENY, service.checkPermission(d4, null, userManager.getPrincipal("testuser1"), permission, permissions, null));
        }
        
        try (CoreSession coreSession = coreFeature.openCoreSession("testuser2")) {
        	Session documentSession = ((AbstractSession) coreSession).getSession();

        	Document d = documentSession.getDocumentByUUID(id1);
        	assertSame(DENY, service.checkPermission(d, null, userManager.getPrincipal("testuser2"), permission, permissions, null));
            
        	Document d2 = documentSession.getDocumentByUUID(id2);
        	assertSame(DENY, service.checkPermission(d2, null, userManager.getPrincipal("testuser2"), permission, permissions, null));
        	
        	Document d3 = documentSession.getDocumentByUUID(id3);
        	assertSame(GRANT, service.checkPermission(d3, null, userManager.getPrincipal("testuser2"), permission, permissions, null));
        	
        	Document d4 = documentSession.getDocumentByUUID(id4);
        	assertSame(DENY, service.checkPermission(d4, null, userManager.getPrincipal("testuser2"), permission, permissions, null));
        }
        
        try (CoreSession coreSession = coreFeature.openCoreSession("user3")) {
        	Session documentSession = ((AbstractSession) coreSession).getSession();

        	Document d = documentSession.getDocumentByUUID(id1);
        	assertSame(DENY, service.checkPermission(d, null, userManager.getPrincipal("testuser3"), permission, permissions, null));
            
        	Document d2 = documentSession.getDocumentByUUID(id2);
        	assertSame(DENY, service.checkPermission(d2, null, userManager.getPrincipal("testuser3"), permission, permissions, null));
        	
        	Document d3 = documentSession.getDocumentByUUID(id3);
        	assertSame(DENY, service.checkPermission(d3, null, userManager.getPrincipal("testuser3"), permission, permissions, null));
        	
        	Document d4 = documentSession.getDocumentByUUID(id4);
        	assertSame(GRANT, service.checkPermission(d4, null, userManager.getPrincipal("testuser3"), permission, permissions, null));
        }
    }
    
    @Test
    public void testTransformer() throws Exception {
    	Transformer t = new AuthLevelTransformer();
    	SQLQuery p = SQLQueryParser.parse("SELECT * FROM File");
    	SQLQuery s = t.transform(userManager.getPrincipal("testuser1"), p);
    	assertTrue(s.toString().contains("WHERE " + AUTH_LEVEL_FIELD + " IS NULL"));
    	assertTrue(s.toString().contains(RIGHTS_DEFAULT));    	
    	assertTrue(s.toString().contains(RIGHTS_GROUP1));
    	
    	s = t.transform(userManager.getPrincipal("testuser3"), p);
    	assertTrue(s.toString().contains("WHERE " + AUTH_LEVEL_FIELD + " IS NULL"));
    	assertFalse(s.toString().contains(RIGHTS_DEFAULT));    	
    	assertFalse(s.toString().contains(RIGHTS_GROUP1));
    	assertTrue(s.toString().contains(RIGHTS_GROUP3));
    }
    
}
