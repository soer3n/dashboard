// Copyright 2025 The Kubermatic Kubernetes Platform contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {Component, OnInit} from '@angular/core';
import {FormControl, FormGroup, Validators} from '@angular/forms';
import {MatDialogRef} from '@angular/material/dialog';
import {NotificationService} from '@app/core/services/notification';
import {SettingsService} from '@app/core/services/settings';
import {Admin} from '@app/shared/entity/member';
import {Observable} from 'rxjs';

@Component({
  selector: 'km-add-global-viewer-dialog',
  templateUrl: './template.html',
  standalone: false,
})
export class AddGlobalViewerDialogComponenet implements OnInit {
  form: FormGroup;

  constructor(
    private readonly _settingsService: SettingsService,
    private readonly _matDialogRef: MatDialogRef<AddGlobalViewerDialogComponenet>,
    private readonly _notificationService: NotificationService
  ) {}

  ngOnInit(): void {
    this.form = new FormGroup({
      email: new FormControl('', [Validators.required, Validators.email]),
    });
  }

  getObservable(): Observable<Admin> {
    return this._settingsService.setAdmin({
      email: this.form.controls.email.value,
      isGlobalViewer: true,
    });
  }

  onNext(adminViewer: Admin): void {
    this._matDialogRef.close(adminViewer);
    this._notificationService.success(`Added the ${adminViewer.name} user to the global viewer group`);
  }
}
