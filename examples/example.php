<?php
/*
+----------------------------------------------------------------------+
| This source file is subject to version 3.0 of the PHP license,       |
| that is bundled with this package in the file LICENSE, and is        |
| available through the world-wide-web at the following url:           |
| http://www.php.net/license/3_0.txt.                                  |
| If you did not receive a copy of the PHP license and are unable to   |
| obtain it through the world-wide-web, please send a note to          |
| license@php.net so we can mail you a copy immediately.               |
+----------------------------------------------------------------------+
| Authors: Andrew Colin Kissa <topdog@fedoraproject.org>               |
+----------------------------------------------------------------------+
*/
	
/* $ Id: */
/*
 Examples on how to use the PHP CouchDB extension
 */
	
/* Create the CouchdbClient object
 The url can support authentication as well 
 - http://user:password@localhost:5984
 
 - Authentication is both by basic and cookie
 To use cookie authentication you need to set use_cookie_auth to true
  CouchdbClient("http://user:pass@localhost:5984",true);
 
 
 The url could be https
 - https://localhost:5984
 You may have to set the CA info using CouchdbClient::setCAPath()

 */
try {
	$conn = new CouchdbClient("http://localhost:5984");
		
	print "Creating Database test_database :";
	if($conn->createDatabase("test_database"))
	print "PASS\n";
	else
	print "FAIL\n";

	echo "Getting Database list\n";
	$result = $conn->listDatabases();
	print_r($result);
	print "===========================\n";

		
	print "Selecting Database test_database\n";
	$conn->selectDB("test_database");
	print "===========================\n";
		
		
	print "Getting Database info\n";
	$result = $conn->getDatabaseInfo();
	print_r($result);
	print "===========================\n";
		
		
	print "Store document to DB\n";
	/* The document can be created in multiple ways
	 - PHP stdclass object
	 - PHP array
	 - JSON encoded string
	 
	 # Using PHP stdclass
	 $new_doc = new stdClass();
	 $new_doc->title = "New content";
	 $new_doc->_id = "BlogPost65";
	 
	 # Using PHP array
	 #$new_doc = array(_id=>Blogpost65,title=>"New content");
	 
	 # Using JSON string
	 $new_doc = '{"_id":"Blogpost65","title":"New content"}';
	*/
	$new_doc = '{"_id":"Blogpost65","title":"New content"}';
	$last_result = $conn->storeDoc($new_doc);
	print_r($last_result);
	print "===========================\n";


	print "Store multiple documents to the DB\n";
	$new_docs = array(array('type'=>'blogpost','title'=>'post'),array('type'=>'blogcomment','blogpost'=>'post','depth'=>1)
					  ,array('type'=>'blogcomment','blogpost'=>'post','depth'=>2));
	$result = $conn->storeDocs($new_docs);
	print_r($result);
	print "===========================\n";
		

	/* run in the examples directory or change the filename */
	print "Store attachment to DB\n";
	$result = $conn->storeAttachment("PHP_LOGO","./php.gif","php.gif","image/gif");
	print_r($result);
	print "===========================\n";
		
		
	print "Copy document to another document\n";
	$result = $conn->copyDoc("Blogpost65","Blogpost66");
	print_r($result);
	print "===========================\n";
		
		
	print "Get all documents in DB\n";
	$result = $conn->getAllDocs();
	print_r($result);
	print "===========================\n";

		
	print "Run a temp view query\n";
	$view = '{"map" : "function(doc) { if (doc.title==\'New content\') { emit(null, doc); } }"}';
	$result = $conn->getTempView($view);
	print_r($result);
	print "===========================\n";
		
		
	print "Delete a document\n";
	$conn->deleteDoc("Blogpost65",$last_result->rev);
	$result = $conn->getLastResponse(true);
	print_r($result);
	print "===========================\n";
		
		
	print "Compacting Database :";
	if($conn->compactDatabase())
	print "PASS\n";
	else
	print "FAIL\n";

	print "===========================\n";
		
		
	print "Getting updated Database info\n";
	$result = $conn->getDatabaseInfo();
	print_r($result);
	print "===========================\n";


	print "Create the replica database - test_replica_database :";
	if($conn->createDatabase("test_replica_database"))
		print "PASS\n";
	else
		print "FAIL\n";
		
		
	print "Start Database replication\n";
	$result = $conn->startReplication("test_database","test_replica_database");
	print_r($conn->getLastResponse(true));
	print "===========================\n";
		

	#print "Sleeping 5 seconds to allow replication to start\n";
	#sleep(5);
	#print "===========================\n";
		
		
	print "Drop the database :";
	if($conn->deleteDatabase("test_database"))
	print "PASS\n";
	else
	print "FAIL\n";

	print "===========================\n";
		
		
	print "Drop the replica database :";
	if($conn->deleteDatabase("test_replica_database"))
	print "PASS\n";
	else
	print "FAIL\n";

	print_r($conn->getLastResponse(true));
	print "===========================\n";
} catch(CouchdbClientException $e) {
	echo $e->getMessage();
}	
unset($conn);
?>
