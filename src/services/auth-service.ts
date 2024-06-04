
import { Auth } from "../modules/auth-module";
import { tokenRepositoryService } from "./token-repository-service";

export const authService: Auth = new Auth(tokenRepositoryService)
