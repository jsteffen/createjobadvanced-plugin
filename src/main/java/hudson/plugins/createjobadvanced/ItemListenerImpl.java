package hudson.plugins.createjobadvanced;

import hudson.Extension;
import hudson.model.Item;
import hudson.model.AbstractItem;
import hudson.model.Hudson;
import hudson.model.Job;
import hudson.model.Run;
import hudson.model.View;
import hudson.model.listeners.ItemListener;
import hudson.scm.SCM;
import hudson.security.Permission;
import hudson.security.SecurityMode;
import hudson.security.AuthorizationMatrixProperty;
import hudson.tasks.LogRotator;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jenkins.model.Jenkins;

import org.kohsuke.stapler.DataBoundConstructor;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.relocate.RelocationAction;
import com.cloudbees.plugins.credentials.CredentialsProvider;

@Extension
public class ItemListenerImpl extends ItemListener {

  static Logger log = Logger.getLogger(CreateJobAdvancedPlugin.class.getName());

  private MavenConfigurer mavenConfigurer = null;


  @DataBoundConstructor
  public ItemListenerImpl() {

    if (Jenkins.getInstance().getPlugin("maven-plugin") != null) {
      mavenConfigurer = new MavenConfigurer();
    }
  }


  @Override
  public void onRenamed(Item item, String oldName, String newName) {

    log.info("renamed " + oldName + " to " + newName);

    if (!(item instanceof Job))
      return;
    final Job<?, ?> job = (Job<?, ?>)item;

    CreateJobAdvancedPlugin cja = getPlugin();
    if (cja.isReplaceSpace()) {
      renameJob(job);
    }
  }


  private CreateJobAdvancedPlugin getPlugin() {

    return Hudson.getInstance().getPlugin(CreateJobAdvancedPlugin.class);
  }


  @Override
  public void onCreated(Item item) {

    log.finer("> ItemListenerImpl.onCreated()");
    CreateJobAdvancedPlugin cja = getPlugin();
    if (item instanceof Job) {
      doAdvancedJob(item, cja);
    } else if (item instanceof Folder) {
      doAdvancedFolder(item, cja);
    }
    log.finer("< ItemListenerImpl.onCreated()");
  }


  private void doAdvancedJob(Item item, CreateJobAdvancedPlugin cja) {

    final Job<?, ?> job = (Job<?, ?>)item;
    if (cja.isReplaceSpace()) {
      renameJob(job);
    }

    // hudson must activate security mode for using
    if (!Hudson.getInstance().getSecurity().equals(SecurityMode.UNSECURED)) {

      if (cja.isAutoOwnerRights()) {
        String sid = Hudson.getAuthentication().getName();
        securityGrantPermissions(job, sid, new Permission[] {
            // Credentials
            // even add these permissions although they currently have no effect
            CredentialsProvider.CREATE, CredentialsProvider.DELETE,
            CredentialsProvider.MANAGE_DOMAINS, CredentialsProvider.UPDATE,
            CredentialsProvider.VIEW,
            // Job
            Item.BUILD, Item.CANCEL, Item.CONFIGURE, Item.DELETE, Item.DISCOVER,
            RelocationAction.RELOCATE, Item.READ, Item.WORKSPACE,
            // Run
            Run.DELETE, Run.UPDATE,
            // SCM
            SCM.TAG
        });
        securityGrantPermissions(job, "anonymous", new Permission[] { Item.READ });
      }

      if (cja.isAutoPublicBrowse()) {
        securityGrantPermissions(job, "anonymous", new Permission[] { Item.READ, Item.WORKSPACE });
      }

      if (cja.isActiveDynamicPermissions()) {
        securityGrantDynamicPermissions(job, cja);
      }
    }

    if (cja.isActiveLogRotator()) {
      activateLogRotator(job, cja);
    }


    if (mavenConfigurer != null) {
      mavenConfigurer.onCreated(job);
    }
  }


  private void securityGrantDynamicPermissions(final AbstractItem item, CreateJobAdvancedPlugin cja) {

    String patternStr = cja.getExtractPattern();// com.([A-Z]{3}).(.*)

    List<String> groupsList = new ArrayList<String>();

    if (patternStr != null) {
      Pattern pattern = Pattern.compile(patternStr);
      Matcher matcher = pattern.matcher(item.getName());
      boolean matchFound = matcher.find();

      if (matchFound) {
        // Get all groups for this match
        for (int i = 0; i <= matcher.groupCount(); i++) {
          String groupStr = matcher.group(i);
          log.log(Level.FINE, "groupStr: " + groupStr);
          groupsList.add(groupStr);
        }
      }
    }

    for (DynamicPermissionConfig dpc : cja.getDynamicPermissionConfigs()) {
      MessageFormat format = new MessageFormat(dpc.getGroupFormat());
      final String newName = format.format(groupsList.toArray(new String[0]));
      log.log(Level.FINE, "add perms for group: " + newName);

      final Set<String> permissions = dpc.getCheckedPermissionIds();
      List<Permission> permissionList = new ArrayList<Permission>();
      for (String id : permissions) {
        final Permission permForId = Permission.fromId(id);
        permissionList.add(permForId);
      }

      if (item instanceof Job) {
        securityGrantPermissions(
            (Job<?, ?>)item, newName,
            (Permission[])permissionList.toArray(new Permission[permissionList.size()]));
      } else if (item instanceof Folder) {
        securityGrantPermissions(
            (Folder)item, newName,
            (Permission[])permissionList.toArray(new Permission[permissionList.size()]));
      }
    }
  }


  private void activateLogRotator(final Job<?, ?> job, final CreateJobAdvancedPlugin cja) {

    // if template, it's possible that log rotator is already defined
    if (job.getLogRotator() != null) {
      return;
    }

    LogRotator logrotator =
        new LogRotator(cja.getDaysToKeep(), cja.getNumToKeep(), cja.getArtifactDaysToKeep(),
            cja.getArtifactNumToKeep());

    try {
      // with 1.503, the signature changed and might now throw an IOException
      job.setLogRotator(logrotator);
    } catch (Exception e) {
      log.log(Level.SEVERE, "error setting Logrotater", e);
    }
  }


  private void renameJob(final Job<?, ?> job) {

    if (job.getName().indexOf(" ") != -1) {
      try {
        job.renameTo(job.getName().replaceAll(" ", "-"));
      } catch (IOException e) {
        log.log(Level.SEVERE, "error during rename", e);
      }
    }
  }


  private void securityGrantPermissions(final Job<?, ?> job, String sid,
      Permission[] hudsonPermissions) {

    Map<Permission, Set<String>> permissions = initPermissions(job);

    for (Permission perm : hudsonPermissions) {
      configurePermission(permissions, perm, sid);
    }

    try {
      AuthorizationMatrixProperty authProperty = new AuthorizationMatrixProperty(permissions);
      job.addProperty(authProperty);
      log.info("Granting rights to [" + sid + "] for newly-created job " + job.getDisplayName());
    } catch (IOException e) {
      log.log(Level.SEVERE, "problem to add granted permissions", e);
    }
  }


  private Map<Permission, Set<String>> initPermissions(final Job<?, ?> job) {

    Map<Permission, Set<String>> permissions = null;

    // if you create the job with template, need to get informations
    AuthorizationMatrixProperty auth =
        (AuthorizationMatrixProperty)job.getProperty(AuthorizationMatrixProperty.class);
    if (auth != null) {
      permissions = new HashMap<Permission, Set<String>>(auth.getGrantedPermissions());
      try {
        job.removeProperty(AuthorizationMatrixProperty.class);
      } catch (IOException e) {
        log.log(Level.SEVERE, "problem to remove granted permissions (template or copy job)", e);
      }
    } else {
      permissions = new HashMap<Permission, Set<String>>();
    }

    return permissions;
  }


  private void configurePermission(Map<Permission, Set<String>> permissions, Permission permission,
      String sid) {

    Set<String> sidPermission = permissions.get(permission);
    if (sidPermission == null) {
      Set<String> sidSet = new HashSet<String>();
      sidSet.add(sid);
      permissions.put(permission, sidSet);
    } else {
      if (!sidPermission.contains(sid)) {
        sidPermission.add(sid);
      }
    }
  }


  private void doAdvancedFolder(Item item, CreateJobAdvancedPlugin cja) {

    final Folder folder = (Folder)item;
    if (cja.isReplaceSpace()) {
      renameFolder(folder);
    }

    // hudson must activate security mode for using
    if (!Hudson.getInstance().getSecurity().equals(SecurityMode.UNSECURED)) {

      if (cja.isAutoOwnerRights()) {
        String sid = Hudson.getAuthentication().getName();
        securityGrantPermissions(folder, sid, new Permission[] {
            // Credentials
            // even add these permissions although they currently have no effect
            CredentialsProvider.CREATE, CredentialsProvider.DELETE,
            CredentialsProvider.MANAGE_DOMAINS, CredentialsProvider.UPDATE,
            CredentialsProvider.VIEW,
            // Job
            Item.BUILD, Item.CANCEL, Item.CONFIGURE, Item.CREATE, Item.DELETE, Item.DISCOVER,
            RelocationAction.RELOCATE, Item.READ, Item.WORKSPACE,
            // View
            View.CONFIGURE, View.CREATE, View.DELETE, View.READ,
            // Run
            Run.DELETE, Run.UPDATE,
            // SCM
            SCM.TAG
        });
        securityGrantPermissions(folder, "anonymous", new Permission[] { Item.READ });
      }

      if (cja.isAutoPublicBrowse()) {
        securityGrantPermissions(folder, "anonymous",
            new Permission[] { Item.READ, Item.WORKSPACE });
      }

      if (cja.isActiveDynamicPermissions()) {
        securityGrantDynamicPermissions(folder, cja);
      }
    }
  }


  private void renameFolder(final Folder folder) {

    if (folder.getName().indexOf(" ") != -1) {
      try {
        folder.renameTo(folder.getName().replaceAll(" ", "-"));
      } catch (IOException e) {
        log.log(Level.SEVERE, "error during rename", e);
      }
    }
  }


  private void securityGrantPermissions(final Folder folder, String sid,
      Permission[] hudsonPermissions) {

    Map<Permission, Set<String>> permissions = initPermissions(folder);

    for (Permission perm : hudsonPermissions) {
      configurePermission(permissions, perm, sid);
    }

    try {
      com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty authProperty =
          new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(
              permissions);
      folder.addProperty(authProperty);
      log.info("Granting rights to [" + sid + "] for newly-created folder "
          + folder.getDisplayName());
    } catch (IOException e) {
      log.log(Level.SEVERE, "problem to add granted permissions", e);
    }
  }


  private Map<Permission, Set<String>> initPermissions(final Folder folder) {

    Map<Permission, Set<String>> permissions = null;

    // if you create the job with template, need to get informations
    com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty auth =
        folder.getProperties().get(
            com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
    if (auth != null) {
      permissions = new HashMap<Permission, Set<String>>(auth.getGrantedPermissions());
      folder.getProperties().remove(auth);
    } else {
      permissions = new HashMap<Permission, Set<String>>();
    }

    return permissions;
  }
}