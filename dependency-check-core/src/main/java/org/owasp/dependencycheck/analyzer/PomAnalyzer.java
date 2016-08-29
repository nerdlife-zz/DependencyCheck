/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.composer.ComposerDependency;
import org.owasp.dependencycheck.data.composer.ComposerException;
import org.owasp.dependencycheck.data.composer.ComposerLockParser;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.owasp.dependencycheck.exception.InitializationException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Used to analyze a pom.xml file for a maven project.
 *
 * @author nerdlife-zz
 */
@Experimental
public class PomAnalyzer extends AbstractFileTypeAnalyzer {
  /**
   * The logger.
   */
  private static final Logger LOGGER = LoggerFactory.getLogger(ComposerLockAnalyzer.class);

  /**
   * The analyzer name.
   */
  private static final String ANALYZER_NAME = "pom.xml analyzer";

  /**
   * The MessageDigest for calculating a new digest for the new dependencies
   * added.
   */
  private MessageDigest sha1 = null;



  /**
   * composer.json.
   */
  private static final String POM_XML = "pom.xml";

  /**
   * The FileFilter.
   */
  private static final FileFilter FILE_FILTER = FileFilterBuilder.newInstance().addFilenames(POM_XML).build();

  /**
   * Returns the FileFilter.
   *
   * @return the FileFilter
   */
  @Override
  protected FileFilter getFileFilter() {
    return FILE_FILTER;
  }

  /**
   * Initializes the analyzer.
   *
   */
  @Override
  protected void initializeFileTypeAnalyzer() throws InitializationException {
    try {
      sha1 = MessageDigest.getInstance("SHA1");
    } catch (NoSuchAlgorithmException ex) {
      setEnabled(false);
      throw new InitializationException("Unable to create SHA1 MmessageDigest", ex);
    }

  }

  private void parseFile(Dependency dependency, Engine engine) {
    try {
      XPathFactory xpathFactory = XPathFactory.newInstance(); 
      XPath xpath = xpathFactory.newXPath();
      XPathExpression artifactIdExpr = xpath.compile("/project/artifactId/text()");
      XPathExpression dependencyExpr = xpath.compile("/project/dependencies/dependency");
      XPathExpression depGroupIdExpr = xpath.compile("./groupId/text()");
      XPathExpression depArtifactIdExpr = xpath.compile("./artifactId/text()");
      XPathExpression depVersionExpr = xpath.compile("./version/text()");

      File f = new File(dependency.getActualFilePath());
      Document document;

      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      document = builder.parse(f);

      // Node projectNode = document.getDocumentElement();
      // NodeList children = projectNode.getChildNodes();

      String projectName = (String)artifactIdExpr.evaluate(document, XPathConstants.STRING);

      List<String> dependencies = new ArrayList<String>();

      NodeList nodes = (NodeList)dependencyExpr.evaluate(document, XPathConstants.NODESET);
      for (int i = 0; i < nodes.getLength(); i++) {
        Node _dependency = nodes.item(i);
        String depGroupId = (String) depGroupIdExpr.evaluate(_dependency,
            XPathConstants.STRING);
        String depArtifactId = (String) depArtifactIdExpr.evaluate(_dependency,
            XPathConstants.STRING);
        String depVersion = (String) depVersionExpr.evaluate(_dependency,
            XPathConstants.STRING);
        String depId = "/" + depGroupId + "/" + depArtifactId + "/" + 
          depVersion + "/" + projectName;
        final Dependency d = new Dependency(dependency.getActualFile());
        d.setDisplayFileName(String.format("%s:%s/%s", dependency.getDisplayFileName(), depGroupId, depArtifactId));
        final String filePath = String.format("%s:%s/%s", dependency.getFilePath(), depGroupId, depArtifactId);
        d.setFilePath(filePath);
        d.setSha1sum(Checksum.getHex(sha1.digest(filePath.getBytes(Charset.defaultCharset()))));
        d.getVendorEvidence().addEvidence(POM_XML, "vendor", depGroupId, Confidence.HIGHEST);
        d.getProductEvidence().addEvidence(POM_XML, "product", depArtifactId, Confidence.HIGHEST);
        d.getVersionEvidence().addEvidence(POM_XML, "version", depVersion, Confidence.HIGHEST);
        LOGGER.info("Adding dependency {}", d);
        engine.getDependencies().add(d);



        dependencies.add(depId);
      }

      for (String  s : dependencies) {
        System.out.println(s);
      }
    } catch (XPathExpressionException e) {
      LOGGER.warn("Error parsing XPATH {}", e);
    } catch (javax.xml.parsers.ParserConfigurationException e) {
      LOGGER.warn("Error with XML parser configuration {}", e);
    } catch (org.xml.sax.SAXException e) {
      LOGGER.warn("Error parsing pom.xml: {}", e);
    } catch (java.io.IOException e) {
      LOGGER.warn("Error reading file {}", e);
    }
  }

  /**
   * Entry point for the analyzer.
   *
   * @param dependency the dependency to analyze
   * @param engine the engine scanning
   * @throws AnalysisException if there's a failure during analysis
   */
  @Override
  protected void analyzeFileType(Dependency dependency, Engine engine) throws AnalysisException {
    System.out.println("AnalyzeFileType called!");
    this.parseFile(dependency, engine); 
    /* FileInputStream fis = null;
       try {
       fis = new FileInputStream(dependency.getActualFile());




       final ComposerLockParser clp = new ComposerLockParser(fis);
       LOGGER.info("Checking composer.lock file {}", dependency.getActualFilePath());
       clp.process();
       for (ComposerDependency dep : clp.getDependencies()) {
       final Dependency d = new Dependency(dependency.getActualFile());
       d.setDisplayFileName(String.format("%s:%s/%s", dependency.getDisplayFileName(), dep.getGroup(), dep.getProject()));
       final String filePath = String.format("%s:%s/%s", dependency.getFilePath(), dep.getGroup(), dep.getProject());
       d.setFilePath(filePath);
       d.setSha1sum(Checksum.getHex(sha1.digest(filePath.getBytes(Charset.defaultCharset()))));
       d.getVendorEvidence().addEvidence(COMPOSER_LOCK, "vendor", dep.getGroup(), Confidence.HIGHEST);
       d.getProductEvidence().addEvidence(COMPOSER_LOCK, "product", dep.getProject(), Confidence.HIGHEST);
       d.getVersionEvidence().addEvidence(COMPOSER_LOCK, "version", dep.getVersion(), Confidence.HIGHEST);
       LOGGER.info("Adding dependency {}", d);
       engine.getDependencies().add(d);
       }
       } catch (FileNotFoundException fnfe) {
       LOGGER.warn("Error opening dependency {}", dependency.getActualFilePath());
       } catch (ComposerException ce) {
       LOGGER.warn("Error parsing composer.json {}", dependency.getActualFilePath(), ce);
       } finally { 
       if (fis != null) {
       try {
       fis.close();
       } catch (Exception e) {
       LOGGER.debug("Unable to close file", e);
       }
       }
       } */
  }
  /**
   * Gets the key to determine whether the analyzer is enabled.
   *
   * @return the key specifying whether the analyzer is enabled
   */
  @Override
  protected String getAnalyzerEnabledSettingKey() {
    return Settings.KEYS.ANALYZER_POM_ENABLED;
  }

  /**
   * Returns the analyzer's name.
   *
   * @return the analyzer's name
   */
  @Override
  public String getName() {
    return ANALYZER_NAME;
  }

  /**
   * Returns the phase this analyzer should run under.
   *
   * @return the analysis phase
   */
  @Override
  public AnalysisPhase getAnalysisPhase() {
    return AnalysisPhase.INFORMATION_COLLECTION;
  }

}
