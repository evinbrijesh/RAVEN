"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import type { Project } from "./types";
import { listProjects, createProject } from "./api-client";

interface ProjectContextValue {
  currentProject: Project;
  projects: Project[];
  setProjectId: (id: string) => void;
  createAndSelectProject: (id: string, name: string, description?: string) => Promise<void>;
  isLoading: boolean;
}

const DEFAULT_PROJECTS: Project[] = [
  {
    project_id: "default",
    name: "Default Project",
    description: "Primary enterprise workspace",
  },
  {
    project_id: "proj_finance",
    name: "Finance Production",
    description: "Payment and refund agent pipeline",
  },
  {
    project_id: "proj_healthcare",
    name: "Healthcare AI",
    description: "Clinical diagnostic assistant",
  },
];

const ProjectContext = createContext<ProjectContextValue | undefined>(undefined);

const STORAGE_KEY = "raven_project_id";

export function ProjectProvider({ children }: { children: React.ReactNode }) {
  const [projects, setProjects] = useState<Project[]>(DEFAULT_PROJECTS);
  const [projectId, setProjectIdState] = useState<string>("default");
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Initialize from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        setProjectIdState(saved);
      }
    } catch {
      // ignore SSR or storage exceptions
    }
  }, []);

  // Fetch registered projects from API
  useEffect(() => {
    let cancelled = false;
    listProjects()
      .then((serverProjects) => {
        if (cancelled || !serverProjects || serverProjects.length === 0) return;
        setProjects((prev) => {
          const map = new Map<string, Project>();
          for (const p of DEFAULT_PROJECTS) map.set(p.project_id, p);
          for (const p of serverProjects) map.set(p.project_id, p);
          return Array.from(map.values());
        });
      })
      .catch(() => {
        // Fallback to default presets if backend offline
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const setProjectId = useCallback((id: string) => {
    setProjectIdState(id);
    try {
      localStorage.setItem(STORAGE_KEY, id);
    } catch {
      // ignore
    }
  }, []);

  const createAndSelectProject = useCallback(
    async (id: string, name: string, description = "") => {
      try {
        const created = await createProject({ project_id: id, name, description });
        setProjects((prev) => {
          if (prev.some((p) => p.project_id === id)) return prev;
          return [...prev, created];
        });
        setProjectId(id);
      } catch {
        // Local fallback if API unavailable
        const localProj: Project = { project_id: id, name, description };
        setProjects((prev) => [...prev, localProj]);
        setProjectId(id);
      }
    },
    [setProjectId],
  );

  const currentProject =
    projects.find((p) => p.project_id === projectId) ??
    projects[0] ?? { project_id: "default", name: "Default Project" };

  return (
    <ProjectContext.Provider
      value={{
        currentProject,
        projects,
        setProjectId,
        createAndSelectProject,
        isLoading,
      }}
    >
      {children}
    </ProjectContext.Provider>
  );
}

export function useProject(): ProjectContextValue {
  const ctx = useContext(ProjectContext);
  if (!ctx) {
    throw new Error("useProject must be used within a ProjectProvider");
  }
  return ctx;
}
